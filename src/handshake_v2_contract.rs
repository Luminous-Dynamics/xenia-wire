// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Independent Xenia Wire reproduction of the candidate dynamically negotiated
//! V2 handshake message and signature-transcript contract.
//!
//! This module intentionally does not call `ViewerHandshake::begin`/`finish` and
//! performs no ML-KEM, signature, or session-key mutation. It exists so Wire can
//! prove byte-level agreement with the independently implemented native contract
//! before production viewer code adopts V2.

#![cfg(feature = "handshake")]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};

use crate::negotiated_context_codec::decode_capability_offer;

/// Existing Xenia unauthenticated handshake envelope ceiling.
pub const MAX_HANDSHAKE_ENVELOPE_BYTES_V2: usize = 16 * 1024;
/// Transport-specific maximum canonical capability-offer bytes in V2.
pub const MAX_V2_CAPABILITY_OFFER_BYTES: usize = 8 * 1024;

const ML_KEM_768_PK_LEN: usize = 1184;
const ML_KEM_768_CT_LEN: usize = 1088;
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

const SIGNATURE_CONTEXT_V2: &[u8] = b"xenia-handshake-signature-v2";
const TRANSCRIPT_SCHEMA_V2: &[u8] = b"xenia-handshake-transcript-v2";
const HANDSHAKE_POLICY_PROFILE: &[u8] = b"hybrid-pq-transcript-v1";
const KEM_SUITE_LABEL: &[u8] = b"ml-kem-768-fips203";
const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &[u8] = b"ed25519-rfc8032+ml-dsa-65-fips204";
const KDF_SUITE_LABEL: &[u8] = b"hkdf-sha256";
const V5_DOMAIN: &[u8] = b"xenia.negotiated-session-context.v5\0";

/// Independent Wire-side HostHelloV2 contract value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHelloV2Contract {
    /// Host Ed25519 verifying key.
    pub ed25519_pk: [u8; 32],
    /// Host ML-DSA-65 verifying key.
    pub ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
    /// Host ML-KEM-768 encapsulation key.
    pub kem_pk: [u8; ML_KEM_768_PK_LEN],
    /// Fresh host nonce.
    pub nonce: [u8; 32],
    /// Existing V4 session-context commitment.
    pub base_v4_context_hash: [u8; 32],
    /// Exact canonical host capability offer bytes.
    pub host_offer: Vec<u8>,
}

/// Independent Wire-side ViewerResponseV2 contract value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerResponseV2Contract {
    /// Viewer Ed25519 verifying key.
    pub ed25519_pk: [u8; 32],
    /// Viewer ML-DSA-65 verifying key.
    pub ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
    /// ML-KEM-768 ciphertext.
    pub kem_ct: [u8; ML_KEM_768_CT_LEN],
    /// Fresh viewer nonce.
    pub nonce: [u8; 32],
    /// Exact canonical viewer capability offer bytes.
    pub viewer_offer: Vec<u8>,
    /// Viewer-recomputed V5 context.
    pub final_v5_context_hash: [u8; 32],
    /// Viewer Ed25519 signature over [`viewer_signature_transcript_v2`].
    pub signature: [u8; 64],
    /// Viewer ML-DSA-65 signature over the identical transcript.
    pub ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

/// Independent Wire-side HostFinalizeV2 contract value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFinalizeV2Contract {
    /// Host-recomputed V5 context.
    pub final_v5_context_hash: [u8; 32],
    /// Host Ed25519 signature over [`host_signature_transcript_v2`].
    pub signature: [u8; 64],
    /// Host ML-DSA-65 signature over the identical transcript.
    pub ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
}

// The first three variants reserve legacy indices. The payload shapes of the
// reserved variants do not affect bincode serialization of variants 3/4/5.
#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum V2WireProbe {
    ReservedLegacyHostHello,
    ReservedLegacyViewerResponse,
    ReservedLegacyHostFinalize,
    HostHelloV2 {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        #[serde(with = "BigArray")]
        kem_pk: [u8; ML_KEM_768_PK_LEN],
        nonce: [u8; 32],
        base_v4_context_hash: [u8; 32],
        host_offer: Vec<u8>,
    },
    ViewerResponseV2 {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        #[serde(with = "BigArray")]
        kem_ct: [u8; ML_KEM_768_CT_LEN],
        nonce: [u8; 32],
        viewer_offer: Vec<u8>,
        final_v5_context_hash: [u8; 32],
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
    HostFinalizeV2 {
        final_v5_context_hash: [u8; 32],
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
}

/// Encode a canonical HostHelloV2 probe using frozen discriminant 3.
pub fn encode_host_hello_v2(message: &HostHelloV2Contract) -> Result<Vec<u8>, V2WireError> {
    validate_hash(&message.base_v4_context_hash)?;
    validate_offer(&message.host_offer)?;
    let bytes = bincode::serialize(&V2WireProbe::HostHelloV2 {
        ed25519_pk: message.ed25519_pk,
        ml_dsa_pk: message.ml_dsa_pk,
        kem_pk: message.kem_pk,
        nonce: message.nonce,
        base_v4_context_hash: message.base_v4_context_hash,
        host_offer: message.host_offer.clone(),
    })?;
    validate_envelope(bytes.len())?;
    Ok(bytes)
}

/// Decode a hostile HostHelloV2 probe and require exact canonical bytes.
pub fn decode_host_hello_v2(bytes: &[u8]) -> Result<HostHelloV2Contract, V2WireError> {
    validate_envelope(bytes.len())?;
    let decoded: V2WireProbe = bincode::deserialize(bytes)?;
    let V2WireProbe::HostHelloV2 {
        ed25519_pk,
        ml_dsa_pk,
        kem_pk,
        nonce,
        base_v4_context_hash,
        host_offer,
    } = decoded
    else {
        return Err(V2WireError::WrongVariant);
    };
    validate_hash(&base_v4_context_hash)?;
    validate_offer(&host_offer)?;
    let message = HostHelloV2Contract {
        ed25519_pk,
        ml_dsa_pk,
        kem_pk,
        nonce,
        base_v4_context_hash,
        host_offer,
    };
    if encode_host_hello_v2(&message)? != bytes {
        return Err(V2WireError::NonCanonicalMessage);
    }
    Ok(message)
}

/// Encode a canonical ViewerResponseV2 probe using frozen discriminant 4.
pub fn encode_viewer_response_v2(
    message: &ViewerResponseV2Contract,
) -> Result<Vec<u8>, V2WireError> {
    validate_hash(&message.final_v5_context_hash)?;
    validate_offer(&message.viewer_offer)?;
    let bytes = bincode::serialize(&V2WireProbe::ViewerResponseV2 {
        ed25519_pk: message.ed25519_pk,
        ml_dsa_pk: message.ml_dsa_pk,
        kem_ct: message.kem_ct,
        nonce: message.nonce,
        viewer_offer: message.viewer_offer.clone(),
        final_v5_context_hash: message.final_v5_context_hash,
        signature: message.signature,
        ml_dsa_signature: message.ml_dsa_signature,
    })?;
    validate_envelope(bytes.len())?;
    Ok(bytes)
}

/// Decode a hostile ViewerResponseV2 probe and require exact canonical bytes.
pub fn decode_viewer_response_v2(bytes: &[u8]) -> Result<ViewerResponseV2Contract, V2WireError> {
    validate_envelope(bytes.len())?;
    let decoded: V2WireProbe = bincode::deserialize(bytes)?;
    let V2WireProbe::ViewerResponseV2 {
        ed25519_pk,
        ml_dsa_pk,
        kem_ct,
        nonce,
        viewer_offer,
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    } = decoded
    else {
        return Err(V2WireError::WrongVariant);
    };
    validate_hash(&final_v5_context_hash)?;
    validate_offer(&viewer_offer)?;
    let message = ViewerResponseV2Contract {
        ed25519_pk,
        ml_dsa_pk,
        kem_ct,
        nonce,
        viewer_offer,
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    };
    if encode_viewer_response_v2(&message)? != bytes {
        return Err(V2WireError::NonCanonicalMessage);
    }
    Ok(message)
}

/// Encode a canonical HostFinalizeV2 probe using frozen discriminant 5.
pub fn encode_host_finalize_v2(message: &HostFinalizeV2Contract) -> Result<Vec<u8>, V2WireError> {
    validate_hash(&message.final_v5_context_hash)?;
    let bytes = bincode::serialize(&V2WireProbe::HostFinalizeV2 {
        final_v5_context_hash: message.final_v5_context_hash,
        signature: message.signature,
        ml_dsa_signature: message.ml_dsa_signature,
    })?;
    validate_envelope(bytes.len())?;
    Ok(bytes)
}

/// Decode a hostile HostFinalizeV2 probe and require exact canonical bytes.
pub fn decode_host_finalize_v2(bytes: &[u8]) -> Result<HostFinalizeV2Contract, V2WireError> {
    validate_envelope(bytes.len())?;
    let decoded: V2WireProbe = bincode::deserialize(bytes)?;
    let V2WireProbe::HostFinalizeV2 {
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    } = decoded
    else {
        return Err(V2WireError::WrongVariant);
    };
    validate_hash(&final_v5_context_hash)?;
    let message = HostFinalizeV2Contract {
        final_v5_context_hash,
        signature,
        ml_dsa_signature,
    };
    if encode_host_finalize_v2(&message)? != bytes {
        return Err(V2WireError::NonCanonicalMessage);
    }
    Ok(message)
}

/// Independently compose V5 from opaque V4 and negotiation-binding commitments.
pub fn compose_v5_context(base_v4: &[u8; 32], binding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(V5_DOMAIN);
    hasher.update(base_v4);
    hasher.update(binding);
    hasher.finalize().into()
}

/// Exact V2 viewer-signature preimage reproduced independently by Wire.
pub fn viewer_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2Contract,
) -> Result<Vec<u8>, V2WireError> {
    let _ = decode_host_hello_v2(hello_bytes)?;
    validate_offer(&response.viewer_offer)?;
    validate_hash(&response.final_v5_context_hash)?;

    let mut out = signature_prefix()?;
    append_len_prefixed(&mut out, b"viewer-response-v2")?;
    append_len_prefixed(&mut out, hello_bytes)?;
    append_len_prefixed(&mut out, &response.ed25519_pk)?;
    append_len_prefixed(&mut out, &response.ml_dsa_pk)?;
    append_len_prefixed(&mut out, &response.kem_ct)?;
    append_len_prefixed(&mut out, &response.nonce)?;
    append_len_prefixed(&mut out, &response.viewer_offer)?;
    append_len_prefixed(&mut out, &response.final_v5_context_hash)?;
    Ok(out)
}

/// Exact V2 host-finalize signature preimage reproduced independently by Wire.
pub fn host_signature_transcript_v2(
    hello_bytes: &[u8],
    response: &ViewerResponseV2Contract,
) -> Result<Vec<u8>, V2WireError> {
    let mut out = viewer_signature_transcript_v2(hello_bytes, response)?;
    append_len_prefixed(&mut out, b"host-finalize-v2")?;
    append_len_prefixed(&mut out, &response.signature)?;
    append_len_prefixed(&mut out, &response.ml_dsa_signature)?;
    append_len_prefixed(&mut out, &response.final_v5_context_hash)?;
    Ok(out)
}

fn signature_prefix() -> Result<Vec<u8>, V2WireError> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, SIGNATURE_CONTEXT_V2)?;
    append_len_prefixed(&mut out, TRANSCRIPT_SCHEMA_V2)?;
    append_len_prefixed(&mut out, HANDSHAKE_POLICY_PROFILE)?;
    append_len_prefixed(&mut out, KEM_SUITE_LABEL)?;
    append_len_prefixed(&mut out, TRANSCRIPT_SIGNATURE_SUITE_LABEL)?;
    append_len_prefixed(&mut out, KDF_SUITE_LABEL)?;
    Ok(out)
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), V2WireError> {
    let len = u32::try_from(bytes.len()).map_err(|_| V2WireError::TranscriptComponentTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_offer(bytes: &[u8]) -> Result<(), V2WireError> {
    if bytes.len() > MAX_V2_CAPABILITY_OFFER_BYTES {
        return Err(V2WireError::OfferTooLarge);
    }
    decode_capability_offer(bytes).map_err(V2WireError::OfferCodec)?;
    Ok(())
}

fn validate_hash(hash: &[u8; 32]) -> Result<(), V2WireError> {
    if hash.iter().all(|byte| *byte == 0) {
        return Err(V2WireError::ZeroContextHash);
    }
    Ok(())
}

fn validate_envelope(len: usize) -> Result<(), V2WireError> {
    if len > MAX_HANDSHAKE_ENVELOPE_BYTES_V2 {
        return Err(V2WireError::EnvelopeTooLarge);
    }
    Ok(())
}

/// Independent Wire V2 contract failure.
#[derive(Debug, thiserror::Error)]
pub enum V2WireError {
    /// Bincode could not encode/decode the exact V2 probe.
    #[error("invalid V2 handshake bincode: {0}")]
    Bincode(#[from] bincode::Error),
    /// Peer offer failed canonical hostile-byte validation.
    #[error("invalid canonical V2 capability offer: {0}")]
    OfferCodec(#[source] crate::negotiated_context_codec::NegotiationCodecError),
    /// Peer offer exceeds the V2 transport-specific cap.
    #[error("V2 capability offer exceeds 8 KiB")]
    OfferTooLarge,
    /// Message exceeds the global unauthenticated handshake ceiling.
    #[error("V2 handshake message exceeds 16 KiB")]
    EnvelopeTooLarge,
    /// Message decoded to a different handshake phase.
    #[error("unexpected V2 handshake message variant")]
    WrongVariant,
    /// Parsed message bytes are not this contract's exact canonical encoding.
    #[error("V2 handshake message is not canonically encoded")]
    NonCanonicalMessage,
    /// V4/V5 context commitment is the all-zero sentinel.
    #[error("V2 context hash must not be all zero")]
    ZeroContextHash,
    /// Signature-transcript component cannot fit its u32 length prefix.
    #[error("V2 transcript component exceeds u32 length bound")]
    TranscriptComponentTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiated_context::{
        CapabilityOfferEntryV1, CapabilityOfferV1, negotiate_capabilities,
    };
    use crate::negotiated_context_codec::encode_capability_offer;

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn independently_reproduces_native_and_node_v2_vectors() {
        let host_offer_semantic = CapabilityOfferV1::from_entries([
            entry(b"xenia.causal-authority", &[b"draft-04", b"draft-03"]),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let viewer_offer_semantic = CapabilityOfferV1::from_entries([
            entry(b"xenia.causal-authority", &[b"draft-04"]),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let negotiation =
            negotiate_capabilities(&host_offer_semantic, &viewer_offer_semantic).unwrap();
        assert_eq!(
            hex(&negotiation.binding_hash()),
            "320f9374b3db961ed169aac86d2c3e6c2c36ea885f143b2dd991c8ee75f3c57b"
        );

        let host_offer = encode_capability_offer(&host_offer_semantic);
        let viewer_offer = encode_capability_offer(&viewer_offer_semantic);
        let mut base_v4 = [0u8; 32];
        for (index, byte) in base_v4.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let v5 = compose_v5_context(&base_v4, &negotiation.binding_hash());
        assert_eq!(
            hex(&v5),
            "9f59efa7ef0959faf57c2490eb438d5537e1485f4bf4f2841cc0df76a647f584"
        );

        let hello = HostHelloV2Contract {
            ed25519_pk: [0x11; 32],
            ml_dsa_pk: [0x22; ML_DSA_65_PK_LEN],
            kem_pk: [0x33; ML_KEM_768_PK_LEN],
            nonce: [0x44; 32],
            base_v4_context_hash: base_v4,
            host_offer,
        };
        let response = ViewerResponseV2Contract {
            ed25519_pk: [0x66; 32],
            ml_dsa_pk: [0x77; ML_DSA_65_PK_LEN],
            kem_ct: [0x88; ML_KEM_768_CT_LEN],
            nonce: [0x99; 32],
            viewer_offer,
            final_v5_context_hash: v5,
            signature: [0xbb; 64],
            ml_dsa_signature: [0xcc; ML_DSA_65_SIG_LEN],
        };
        let finalize = HostFinalizeV2Contract {
            final_v5_context_hash: v5,
            signature: [0xdd; 64],
            ml_dsa_signature: [0xee; ML_DSA_65_SIG_LEN],
        };

        let hello_bytes = encode_host_hello_v2(&hello).unwrap();
        let response_bytes = encode_viewer_response_v2(&response).unwrap();
        let finalize_bytes = encode_host_finalize_v2(&finalize).unwrap();
        assert_eq!(&hello_bytes[..4], &3u32.to_le_bytes());
        assert_eq!(&response_bytes[..4], &4u32.to_le_bytes());
        assert_eq!(&finalize_bytes[..4], &5u32.to_le_bytes());
        assert_eq!(hello_bytes.len(), 3348);
        assert_eq!(response_bytes.len(), 6615);
        assert_eq!(finalize_bytes.len(), 3409);
        assert_eq!(
            hex(&Sha256::digest(&hello_bytes)),
            "c63e7bd4a331f03bdf295ee0845a08eb936a9625d7a8bc413a14c13166c25b0a"
        );
        assert_eq!(
            hex(&Sha256::digest(&response_bytes)),
            "7e3ab9366d8336e284a5ba595ffa505610f43869a5c66fbbf942bc69e7049b0b"
        );
        assert_eq!(
            hex(&Sha256::digest(&finalize_bytes)),
            "ec55f4899e10022511681709db3d496c96b7e20faa35ba573e12f3e994782b44"
        );

        let viewer_transcript = viewer_signature_transcript_v2(&hello_bytes, &response).unwrap();
        let host_transcript = host_signature_transcript_v2(&hello_bytes, &response).unwrap();
        assert_eq!(viewer_transcript.len(), 6794);
        assert_eq!(host_transcript.len(), 10231);
        assert_eq!(
            hex(&Sha256::digest(&viewer_transcript)),
            "fccfc6314ddcf38c5464fca454343c95716e191c8afeac22f96be49ac49c8456"
        );
        assert_eq!(
            hex(&Sha256::digest(&host_transcript)),
            "add97be37fb648148d5cb7c80f41d283187ad1e744cbd317b98fa6dc09a9f364"
        );
    }

    #[test]
    fn malformed_or_wrong_phase_bytes_fail_closed() {
        let offer =
            CapabilityOfferV1::from_entries([entry(b"xenia.causal-authority", &[b"draft-04"])])
                .unwrap();
        let mut hello = HostHelloV2Contract {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            base_v4_context_hash: [5; 32],
            host_offer: encode_capability_offer(&offer),
        };
        let bytes = encode_host_hello_v2(&hello).unwrap();
        assert!(matches!(
            decode_viewer_response_v2(&bytes),
            Err(V2WireError::WrongVariant)
        ));
        hello.host_offer.push(0xa5);
        assert!(matches!(
            encode_host_hello_v2(&hello),
            Err(V2WireError::OfferCodec(_))
        ));
    }
}
