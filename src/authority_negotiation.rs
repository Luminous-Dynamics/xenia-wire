// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Causal-authority capability policy for Xenia handshake negotiation.
//!
//! This module is available only when both `causal-authority` and `handshake`
//! are enabled. It defines the exact draft-04 capability identity and two
//! deliberately different trust levels:
//!
//! - [`require_causal_authority_draft04_evidence`] checks a deterministic
//!   [`NegotiationEvidenceV1`] derived from both peer offers. The evidence is
//!   canonical but is not authenticated until a future V2 handshake transcript
//!   covers its negotiation binding.
//! - [`PinnedCausalAuthorityViewerHandshake`] is a legacy/pre-agreed mode. It
//!   proves only that the existing host handshake authenticated a caller-pinned
//!   selected-context hash. It is **not** dynamic two-offer negotiation.
//!
//! The distinction is load-bearing. A host-authenticated opaque hash can prove
//! agreement with a preconfigured expectation, but it cannot prove what the
//! viewer offered because the legacy HostHello is emitted before any viewer
//! capability offer exists.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::handshake::{HandshakeError, SessionKeySchedule, ViewerHandshake};
use crate::negotiated_context::{
    CapabilityOfferEntryV1, NegotiatedCapabilityV1, NegotiatedContextError, NegotiatedContextV1,
    NegotiationEvidenceV1,
};

/// Canonical capability name for request-bound causal authority.
pub const CAUSAL_AUTHORITY_CAPABILITY_NAME: &[u8] = b"xenia.causal-authority";

/// Canonical capability version for the draft-04 candidate protocol.
pub const CAUSAL_AUTHORITY_CAPABILITY_VERSION: &[u8] = b"draft-04";

// Wire sizes copied from the legacy handshake protocol solely for fail-closed
// pinned HostHello preflight decoding. This mirror is temporary and should
// disappear when the V2 handshake exposes typed negotiated evidence directly.
const ML_KEM_768_PK_LEN: usize = 1184;
const ML_KEM_768_CT_LEN: usize = 1088;
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

/// Private probe matching the legacy `handshake::HandshakeMessage`
/// field-for-field under bincode v1.
///
/// This supports only the pre-agreed pinned-context compatibility path. It must
/// not be extended into the V2 dynamic negotiation implementation; V2 should
/// expose its own typed handshake messages rather than mirror private enums.
#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum LegacyHandshakeContextProbe {
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

/// Construct the exact draft-04 causal-authority selected capability identifier.
pub fn causal_authority_draft04_capability() -> NegotiatedCapabilityV1 {
    NegotiatedCapabilityV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec(),
    )
    .expect("built-in causal-authority capability satisfies negotiated-context bounds")
}

/// Construct the exact draft-04 causal-authority offer entry.
///
/// A strict V2 peer should include this entry in its canonical offer. Both peers
/// must offer the exact version and deterministic selection must choose it before
/// causal authority can be enabled.
pub fn causal_authority_draft04_offer_entry() -> CapabilityOfferEntryV1 {
    CapabilityOfferEntryV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        [CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec()],
    )
    .expect("built-in causal-authority offer satisfies negotiated-context bounds")
}

/// Require exact causal-authority draft-04 in a canonical selected context.
///
/// This proves only membership in the supplied selected context. Prefer
/// [`require_causal_authority_draft04_evidence`] when both peer offers are
/// available so the selection itself has been deterministically recomputed.
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

/// Require exact causal-authority draft-04 in deterministic two-offer evidence.
///
/// [`NegotiationEvidenceV1`] can only be produced from the canonical host and
/// viewer offers plus deterministic mutual selection, so this is stronger than
/// checking a caller-manufactured selected context. The evidence still becomes
/// *authenticated proof* only when the V2 handshake covers its binding hash.
pub fn require_causal_authority_draft04_evidence(
    evidence: &NegotiationEvidenceV1,
) -> Result<(), AuthorityNegotiationError> {
    require_causal_authority_draft04(evidence.selected_context())
}

/// Build a canonical selected context and require exact causal-authority
/// draft-04 membership.
///
/// This helper is useful for pre-agreed/pinned policy and deterministic vectors.
/// It does not prove that a remote peer offered the resulting capability set.
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

/// Viewer-side **pre-agreed pinned-context** handshake compatibility wrapper.
///
/// This wrapper refuses to sign a legacy HostHello unless its transcript-bound
/// opaque context hash exactly equals a caller-preconfigured selected context.
/// That is useful for static deployments where both sides are configured out of
/// band, but it is not dynamic capability negotiation because the viewer never
/// contributes an authenticated offer to the legacy ceremony.
///
/// New consequential deployments should migrate to the V2 two-offer handshake
/// tracked by `xenia-peer#148` once that ceremony is implemented and validated.
pub struct PinnedCausalAuthorityViewerHandshake {
    inner: ViewerHandshake,
    expected_context: NegotiatedContextV1,
}

impl PinnedCausalAuthorityViewerHandshake {
    /// Generate a fresh viewer identity and pin the supplied selected capability
    /// context, which must contain exact causal-authority draft-04.
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
    /// pin the supplied selected capability context.
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

    /// Canonical selected context pinned by this compatibility handshake.
    pub fn expected_context(&self) -> &NegotiatedContextV1 {
        &self.expected_context
    }

    /// Process legacy HostHello only if its transcript-bound context exactly
    /// matches the pinned causal-authority selected context.
    ///
    /// The check occurs before `ViewerHandshake::begin` signs HostHello. It
    /// proves a pre-agreed context match only; it does not create a viewer offer.
    pub fn begin(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, AuthorityHandshakeError> {
        let observed = observed_context_from_legacy_host_hello(hello_bytes)?;
        self.expected_context
            .require_observed_hash(observed)
            .map_err(AuthorityNegotiationError::from)?;
        Ok(self.inner.begin(hello_bytes)?)
    }

    /// Verify legacy HostFinalize and yield a typed proof of the authenticated
    /// **pinned** selected context.
    ///
    /// The result intentionally is not named a negotiated-handshake proof; it
    /// carries no authenticated viewer offer and therefore cannot satisfy V2's
    /// dynamic negotiation claim.
    pub fn finish(
        &mut self,
        finalize_bytes: &[u8],
    ) -> Result<AuthenticatedPinnedCausalAuthorityContext, AuthorityHandshakeError> {
        let key_schedule = self.inner.finish(finalize_bytes)?;
        Ok(AuthenticatedPinnedCausalAuthorityContext {
            key_schedule,
            pinned_selected_context: self.expected_context.clone(),
        })
    }
}

/// Successful legacy handshake proof for a pre-agreed pinned authority context.
///
/// This type has no public constructor. Safe Rust callers obtain it only after
/// [`PinnedCausalAuthorityViewerHandshake::finish`] verifies the normal hybrid-PQ
/// host finalize after the pinned HostHello context check.
///
/// It is **not** evidence that both peers dynamically offered or negotiated the
/// capability. V2 will use a distinct authenticated negotiation proof type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPinnedCausalAuthorityContext {
    key_schedule: SessionKeySchedule,
    pinned_selected_context: NegotiatedContextV1,
}

impl AuthenticatedPinnedCausalAuthorityContext {
    /// Transcript-bound session key schedule from the authenticated handshake.
    pub fn key_schedule(&self) -> &SessionKeySchedule {
        &self.key_schedule
    }

    /// Pre-agreed selected context whose hash the host authenticated.
    pub fn pinned_selected_context(&self) -> &NegotiatedContextV1 {
        &self.pinned_selected_context
    }

    /// Consume the proof and return the key schedule for session installation.
    pub fn into_key_schedule(self) -> SessionKeySchedule {
        self.key_schedule
    }
}

/// Compatibility alias for the earlier overly broad type name.
///
/// The old name suggested dynamic negotiation. It is retained temporarily so
/// draft consumers can migrate, but its semantics are only pinned-context
/// authentication.
#[deprecated(
    note = "this legacy wrapper authenticates only a pre-agreed HostHello context; use PinnedCausalAuthorityViewerHandshake or the future V2 two-offer handshake for real negotiation"
)]
pub type StrictCausalAuthorityViewerHandshake = PinnedCausalAuthorityViewerHandshake;

/// Compatibility alias for the earlier overly broad proof name.
///
/// This proof authenticates a pinned context, not a two-offer negotiated result.
#[deprecated(
    note = "this is pinned-context authentication, not dynamic negotiation; use AuthenticatedPinnedCausalAuthorityContext or the future V2 authenticated negotiation proof"
)]
pub type AuthenticatedCausalAuthorityHandshake = AuthenticatedPinnedCausalAuthorityContext;

fn observed_context_from_legacy_host_hello(
    hello_bytes: &[u8],
) -> Result<Option<[u8; 32]>, AuthorityHandshakeError> {
    let message: LegacyHandshakeContextProbe =
        bincode::deserialize(hello_bytes).map_err(HandshakeError::from)?;
    match message {
        LegacyHandshakeContextProbe::HostHello {
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
    #[error("causal-authority draft-04 was not selected")]
    CausalAuthorityNotNegotiated,
}

/// Pinned-context causal-authority handshake failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityHandshakeError {
    /// Canonical policy construction or pinned-context verification failed.
    #[error(transparent)]
    Negotiation(#[from] AuthorityNegotiationError),
    /// The underlying Xenia hybrid-PQ handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiated_context::{CapabilityOfferV1, negotiate_capabilities};

    fn offer_entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    #[test]
    fn exact_draft04_capability_is_required() {
        let context = NegotiatedContextV1::from_capabilities([NegotiatedCapabilityV1::new(
            b"xenia.causal-authority".to_vec(),
            b"draft-03".to_vec(),
        )
        .unwrap()])
        .unwrap();

        assert_eq!(
            require_causal_authority_draft04(&context).unwrap_err(),
            AuthorityNegotiationError::CausalAuthorityNotNegotiated
        );
    }

    #[test]
    fn two_offer_evidence_requires_exact_mutual_draft04() {
        let host = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-03"],
        )])
        .unwrap();
        let viewer =
            CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap();
        let evidence = negotiate_capabilities(&host, &viewer).unwrap();
        assert!(require_causal_authority_draft04_evidence(&evidence).is_ok());

        let downgraded_viewer = CapabilityOfferV1::from_entries([offer_entry(
            b"xenia.causal-authority",
            &[b"draft-03"],
        )])
        .unwrap();
        let downgraded = negotiate_capabilities(&host, &downgraded_viewer).unwrap();
        assert_eq!(
            require_causal_authority_draft04_evidence(&downgraded).unwrap_err(),
            AuthorityNegotiationError::CausalAuthorityNotNegotiated
        );
    }

    #[test]
    fn additional_selected_capabilities_are_bound_into_hash() {
        let authority_only =
            causal_authority_context([causal_authority_draft04_capability()]).unwrap();
        let authority_plus_rekey = causal_authority_context([
            causal_authority_draft04_capability(),
            NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec()).unwrap(),
        ])
        .unwrap();

        assert_ne!(authority_only.hash(), authority_plus_rekey.hash());
        assert!(require_causal_authority_draft04(&authority_plus_rekey).is_ok());
    }

    #[test]
    fn legacy_host_hello_preflight_extracts_exact_pinned_context() {
        let context = causal_authority_context([causal_authority_draft04_capability()]).unwrap();
        let hello = LegacyHandshakeContextProbe::HostHello {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            negotiated_context_hash: Some(context.hash()),
        };
        let bytes = bincode::serialize(&hello).unwrap();
        assert_eq!(
            observed_context_from_legacy_host_hello(&bytes).unwrap(),
            Some(context.hash())
        );
    }

    #[test]
    fn pinned_preflight_rejects_missing_or_wrong_context_before_signing() {
        let context = causal_authority_context([causal_authority_draft04_capability()]).unwrap();
        let missing = LegacyHandshakeContextProbe::HostHello {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            negotiated_context_hash: None,
        };
        let wrong = LegacyHandshakeContextProbe::HostHello {
            ed25519_pk: [1; 32],
            ml_dsa_pk: [2; ML_DSA_65_PK_LEN],
            kem_pk: [3; ML_KEM_768_PK_LEN],
            nonce: [4; 32],
            negotiated_context_hash: Some([0xA5; 32]),
        };

        assert_eq!(
            context
                .require_observed_hash(
                    observed_context_from_legacy_host_hello(&bincode::serialize(&missing).unwrap())
                        .unwrap()
                )
                .unwrap_err(),
            NegotiatedContextError::MissingNegotiatedContext
        );
        assert_eq!(
            context
                .require_observed_hash(
                    observed_context_from_legacy_host_hello(&bincode::serialize(&wrong).unwrap())
                        .unwrap()
                )
                .unwrap_err(),
            NegotiatedContextError::NegotiatedContextMismatch
        );
    }
}
