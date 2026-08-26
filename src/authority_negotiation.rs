// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Causal-authority capability profile for authenticated handshake negotiation.
//!
//! This module is available only when both `causal-authority` and `handshake`
//! are enabled. It defines the exact capability identifier that a strict
//! draft-04 deployment must include in its authenticated negotiated context.
//!
//! The helpers here intentionally do not accept a boolean such as
//! `supports_causal_authority`. Authority availability is represented by exact
//! canonical bytes inside [`crate::negotiated_context::NegotiatedContextV1`].
//! [`StrictCausalAuthorityViewerHandshake`] additionally proves that the host's
//! signed handshake carried that exact context before yielding an
//! [`AuthenticatedCausalAuthorityHandshake`] token.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::handshake::{HandshakeError, SessionKeySchedule, ViewerHandshake};
use crate::negotiated_context::{
    NegotiatedCapabilityV1, NegotiatedContextError, NegotiatedContextV1,
};

/// Canonical capability name for request-bound causal authority.
pub const CAUSAL_AUTHORITY_CAPABILITY_NAME: &[u8] = b"xenia.causal-authority";

/// Canonical capability version for the draft-04 candidate protocol.
pub const CAUSAL_AUTHORITY_CAPABILITY_VERSION: &[u8] = b"draft-04";

// Wire sizes copied from the handshake protocol solely for fail-closed
// HostHello preflight decoding. A conformance test below freezes the shape.
const ML_KEM_768_PK_LEN: usize = 1184;
const ML_KEM_768_CT_LEN: usize = 1088;
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

/// Private probe matching `handshake::HandshakeMessage` field-for-field under
/// bincode v1. It exists because the public viewer API intentionally hides raw
/// handshake internals, while strict authority needs to reject a wrong context
/// *before* the viewer signs the HostHello.
#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum HandshakeContextProbe {
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

/// Construct the exact draft-04 causal-authority capability identifier.
pub fn causal_authority_draft04_capability() -> NegotiatedCapabilityV1 {
    NegotiatedCapabilityV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec(),
    )
    .expect("built-in causal-authority capability satisfies negotiated-context bounds")
}

/// Require that a canonical selected-capability context contains exact
/// causal-authority draft-04 support.
///
/// This proves only membership in the supplied canonical context. The context's
/// hash must additionally be authenticated by the handshake transcript before
/// an application treats the capability as negotiated.
pub fn require_causal_authority_draft04(
    context: &NegotiatedContextV1,
) -> Result<(), AuthorityNegotiationError> {
    if context.contains(
        CAUSAL_AUTHORITY_CAPABILITY_NAME,
        CAUSAL_AUTHORITY_CAPABILITY_VERSION,
    ) {
        Ok(())
    } else {
        Err(AuthorityNegotiationError::CausalAuthorityNotNegotiated)
    }
}

/// Build a canonical selected context and require exact causal-authority
/// draft-04 membership.
///
/// Additional capabilities are preserved and therefore affect the context hash;
/// this prevents a caller from checking only a special-case authority bit while
/// ignoring the rest of the negotiated protocol surface.
pub fn causal_authority_context<I>(
    capabilities: I,
) -> Result<NegotiatedContextV1, AuthorityNegotiationError>
where
    I: IntoIterator<Item = NegotiatedCapabilityV1>,
{
    let context = NegotiatedContextV1::from_capabilities(capabilities)?;
    require_causal_authority_draft04(&context)?;
    Ok(context)
}

/// Viewer-side handshake that refuses to sign a HostHello unless it carries the
/// exact expected causal-authority negotiated context.
///
/// The ordinary [`ViewerHandshake`] remains available for non-authority use.
/// Consequential external-action clients should prefer this wrapper once the
/// native host has been configured to derive the same canonical context hash.
pub struct StrictCausalAuthorityViewerHandshake {
    inner: ViewerHandshake,
    expected_context: NegotiatedContextV1,
}

impl StrictCausalAuthorityViewerHandshake {
    /// Generate a fresh viewer identity and require the supplied selected
    /// capability set, which must contain exact causal-authority draft-04.
    pub fn new<I>(capabilities: I) -> Result<Self, AuthorityHandshakeError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        Ok(Self {
            inner: ViewerHandshake::new(),
            expected_context: causal_authority_context(capabilities)?,
        })
    }

    /// Reconstruct the viewer identity from persisted Ed25519/ML-DSA seeds and
    /// require the supplied selected capability set.
    pub fn from_identity<I>(
        ed25519_secret: &[u8],
        ml_dsa_seed: &[u8],
        capabilities: I,
    ) -> Result<Self, AuthorityHandshakeError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        Ok(Self {
            inner: ViewerHandshake::from_identity(ed25519_secret, ml_dsa_seed)?,
            expected_context: causal_authority_context(capabilities)?,
        })
    }

    /// Viewer Ed25519 public key for operator enrollment.
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        self.inner.ed25519_public_key()
    }

    /// Canonical capability context that this handshake requires.
    pub fn expected_context(&self) -> &NegotiatedContextV1 {
        &self.expected_context
    }

    /// Process HostHello only if its transcript-bound context exactly matches
    /// this strict causal-authority profile.
    ///
    /// The preflight happens before `ViewerHandshake::begin` signs HostHello,
    /// preventing a viewer from accidentally consenting to a downgraded context
    /// and detecting it only after doing cryptographic work.
    pub fn begin(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, AuthorityHandshakeError> {
        let observed = observed_context_from_host_hello(hello_bytes)?;
        self.expected_context
            .require_observed_hash(observed)
            .map_err(AuthorityNegotiationError::from)?;
        Ok(self.inner.begin(hello_bytes)?)
    }

    /// Verify HostFinalize and yield a typed proof that the strict expected
    /// causal-authority context participated in the authenticated handshake.
    pub fn finish(
        &mut self,
        finalize_bytes: &[u8],
    ) -> Result<AuthenticatedCausalAuthorityHandshake, AuthorityHandshakeError> {
        let key_schedule = self.inner.finish(finalize_bytes)?;
        Ok(AuthenticatedCausalAuthorityHandshake {
            key_schedule,
            negotiated_context: self.expected_context.clone(),
        })
    }
}

/// Successful strict handshake proof for downstream authority-aware code.
///
/// This type has no public constructor. Safe Rust callers obtain it only after
/// [`StrictCausalAuthorityViewerHandshake::finish`] verifies the ordinary Xenia
/// hybrid-PQ handshake signatures after the strict HostHello context preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCausalAuthorityHandshake {
    key_schedule: SessionKeySchedule,
    negotiated_context: NegotiatedContextV1,
}

impl AuthenticatedCausalAuthorityHandshake {
    /// Transcript-bound session key schedule from the authenticated handshake.
    pub fn key_schedule(&self) -> &SessionKeySchedule {
        &self.key_schedule
    }

    /// Canonical selected capabilities authenticated by the strict handshake.
    pub fn negotiated_context(&self) -> &NegotiatedContextV1 {
        &self.negotiated_context
    }

    /// Consume the proof and return the key schedule for session installation.
    pub fn into_key_schedule(self) -> SessionKeySchedule {
        self.key_schedule
    }
}

fn observed_context_from_host_hello(
    hello_bytes: &[u8],
) -> Result<Option<[u8; 32]>, AuthorityHandshakeError> {
    let message: HandshakeContextProbe = bincode::deserialize(hello_bytes)
        .map_err(HandshakeError::from)?;
    match message {
        HandshakeContextProbe::HostHello {
            negotiated_context_hash,
            ..
        } => Ok(negotiated_context_hash),
        _ => Err(HandshakeError::ExpectedHostHello.into()),
    }
}

/// Causal-authority negotiation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityNegotiationError {
    /// Canonical context construction or digest verification failed.
    #[error(transparent)]
    Context(#[from] NegotiatedContextError),
    /// The selected capability set does not contain exact draft-04 causal
    /// authority support.
    #[error("causal-authority draft-04 was not negotiated")]
    CausalAuthorityNotNegotiated,
}

/// Strict causal-authority handshake failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityHandshakeError {
    /// Canonical negotiation profile construction or verification failed.
    #[error(transparent)]
    Negotiation(#[from] AuthorityNegotiationError),
    /// The underlying Xenia hybrid-PQ handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_draft04_capability_is_required() {
        let context = NegotiatedContextV1::from_capabilities([
            NegotiatedCapabilityV1::new(b"xenia.causal-authority".to_vec(), b"draft-03".to_vec())
                .unwrap(),
        ])
        .unwrap();

        assert_eq!(
            require_causal_authority_draft04(&context).unwrap_err(),
            AuthorityNegotiationError::CausalAuthorityNotNegotiated
        );
    }

    #[test]
    fn additional_selected_capabilities_are_bound_into_hash() {
        let authority_only = causal_authority_context([causal_authority_draft04_capability()])
            .unwrap();
        let authority_plus_rekey = causal_authority_context([
            causal_authority_draft04_capability(),
            NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec())
                .unwrap(),
        ])
        .unwrap();

        assert_ne!(authority_only.hash(), authority_plus_rekey.hash());
        assert!(require_causal_authority_draft04(&authority_plus_rekey).is_ok());
    }

    #[test]
    fn host_hello_preflight_extracts_exact_context() {
        let context = causal_authority_context([causal_authority_draft04_capability()]).unwrap();
        let hello = HandshakeContextProbe::HostHello {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            negotiated_context_hash: Some(context.hash()),
        };
        let bytes = bincode::serialize(&hello).unwrap();
        assert_eq!(observed_context_from_host_hello(&bytes).unwrap(), Some(context.hash()));
    }

    #[test]
    fn strict_viewer_rejects_missing_or_downgraded_context_before_signing() {
        let context = causal_authority_context([causal_authority_draft04_capability()]).unwrap();
        let missing = HandshakeContextProbe::HostHello {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            negotiated_context_hash: None,
        };
        let wrong = HandshakeContextProbe::HostHello {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            negotiated_context_hash: Some([0xA5; 32]),
        };

        assert_eq!(
            context
                .require_observed_hash(observed_context_from_host_hello(&bincode::serialize(&missing).unwrap()).unwrap())
                .unwrap_err(),
            NegotiatedContextError::MissingNegotiatedContext
        );
        assert_eq!(
            context
                .require_observed_hash(observed_context_from_host_hello(&bincode::serialize(&wrong).unwrap()).unwrap())
                .unwrap_err(),
            NegotiatedContextError::NegotiatedContextMismatch
        );
    }
}
