// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Public type-state facade for exact authority bound to a live Xenia Wire session.
//!
//! Low-level request/session helpers remain available with `causal-authority`
//! alone. With `handshake` enabled, the generic staged implementation remains
//! private and the public path enforces two additional invariants:
//!
//! 1. [`crate::Session`] is a single-AEAD-key envelope session, so its
//!    authority-preserving rekey domain is operator-channel only. Multi-lane
//!    `LaneSessionV1` authority belongs to xenia-peer's native lane-session layer.
//! 2. An authenticated V2 proof cannot be attached to an arbitrary pre-keyed
//!    session. The proof must consume an *unkeyed* [`crate::Session`] and install
//!    its private authenticated schedule itself before local authority policy may
//!    narrow the session into [`NegotiatedAuthoritySession`].

#[path = "authority_session_impl.rs"]
mod private_impl;

pub use private_impl::{
    AuthoritySessionError, sign_causal_authority_response_for_session,
    verify_approved_external_action_authority_for_session,
};

#[cfg(feature = "handshake")]
pub use private_impl::NegotiatedAuthoritySessionError;

#[cfg(feature = "handshake")]
use zeroize::Zeroizing;
#[cfg(feature = "handshake")]
use crate::Session;
#[cfg(feature = "handshake")]
use crate::authority::{CausalAuthorityResponse, VerifiedExternalActionAuthority};
#[cfg(feature = "handshake")]
use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
#[cfg(feature = "handshake")]
use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
#[cfg(feature = "handshake")]
use crate::authority_rekey_profile_binding::AuthorityRekeyProfileBindingV1;
#[cfg(feature = "handshake")]
use crate::authority_rekey_transition_evidence::RekeyTransitionProfileV1;
#[cfg(feature = "handshake")]
use crate::consent::{ConsentRequest, ConsentRevocation, PUBLIC_KEY_LEN};
#[cfg(feature = "handshake")]
use crate::handshake::SessionKeySchedule;
#[cfg(feature = "handshake")]
use crate::negotiated_context::{CapabilityOfferV1, NegotiatedContextV1};
#[cfg(feature = "handshake")]
use crate::negotiation_policy::NegotiationPolicyV1;

/// Failure while moving authenticated negotiation through the public session
/// installation/type-state boundary.
#[cfg(feature = "handshake")]
#[derive(Debug, thiserror::Error)]
pub enum AuthoritySessionTransitionError {
    /// The private negotiated-authority state rejected the transition.
    #[error(transparent)]
    State(#[from] NegotiatedAuthoritySessionError),
    /// The authenticated session schedule carried an unusable all-zero rekey root.
    #[error("authenticated V2 session schedule contains an all-zero rekey root")]
    ZeroRekeyRoot,
    /// V2 installation is single-use and must target an unkeyed session.
    #[error("authenticated V2 negotiation can only install into an unkeyed Xenia session")]
    SessionAlreadyKeyed,
}

/// Authenticated facts produced by a completed dynamic V2 handshake.
///
/// This public proof has no public constructor and is not serializable. The
/// future V2 state machine may construct it only after both transcript signature
/// suites verify. It retains the authenticated AEAD key privately until
/// [`Self::install_into`] consumes the proof.
#[cfg(feature = "handshake")]
pub struct AuthenticatedNegotiatedHandshake {
    inner: private_impl::AuthenticatedNegotiatedHandshake,
    session_aead_key: Zeroizing<[u8; 32]>,
    session_rekey_root: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "handshake")]
impl AuthenticatedNegotiatedHandshake {
    /// Construct the public type-state proof from facts already authenticated by
    /// the real V2 cryptographic state machine.
    pub(crate) fn from_verified_v2_parts(
        host_offer: CapabilityOfferV1,
        viewer_offer: CapabilityOfferV1,
        base_v4_context_hash: [u8; 32],
        observed_final_v5_context_hash: [u8; 32],
        key_schedule: SessionKeySchedule,
    ) -> Result<Self, AuthoritySessionTransitionError> {
        if key_schedule.rekey.iter().all(|byte| *byte == 0) {
            return Err(AuthoritySessionTransitionError::ZeroRekeyRoot);
        }
        let aead = Zeroizing::new(key_schedule.aead);
        let rekey = Zeroizing::new(key_schedule.rekey);
        let inner = private_impl::AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host_offer,
            viewer_offer,
            base_v4_context_hash,
            observed_final_v5_context_hash,
            key_schedule,
        )?;
        Ok(Self {
            inner,
            session_aead_key: aead,
            session_rekey_root: rekey,
        })
    }

    /// Authenticated selected capability context.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        self.inner.selected_context()
    }

    /// Authenticated V5 session-context commitment.
    pub fn final_v5_context_hash(&self) -> &[u8; 32] {
        self.inner.final_v5_context_hash()
    }

    /// Consume this single-use handshake proof and install its authenticated AEAD
    /// key into an unkeyed raw session.
    ///
    /// The caller chooses the session's local nonce-domain identity by creating
    /// the raw session, but never receives the authenticated key from this API.
    /// A pre-keyed or cloned-key session is rejected rather than rebound.
    pub fn install_into(
        self,
        mut session: Session,
    ) -> Result<InstalledNegotiatedSession, AuthoritySessionTransitionError> {
        if session.has_key() {
            return Err(AuthoritySessionTransitionError::SessionAlreadyKeyed);
        }
        session.install_key(*self.session_aead_key);
        Ok(InstalledNegotiatedSession {
            session,
            negotiation: self.inner,
            session_rekey_root: self.session_rekey_root,
        })
    }
}

/// Authenticated V2 negotiation whose private schedule has been installed into
/// exactly one owned raw session, but whose local causal-authority policy has not
/// yet been accepted.
#[cfg(feature = "handshake")]
pub struct InstalledNegotiatedSession {
    session: Session,
    negotiation: private_impl::AuthenticatedNegotiatedHandshake,
    session_rekey_root: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "handshake")]
impl InstalledNegotiatedSession {
    /// Authenticated selected capability context available for local policy review.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        self.negotiation.selected_context()
    }

    /// Authenticated V5 commitment for this installed transport session.
    pub fn final_v5_context_hash(&self) -> &[u8; 32] {
        self.negotiation.final_v5_context_hash()
    }

    /// Consume installed negotiation through local policy and create the only
    /// public authority-capable Wire session type.
    ///
    /// The private implementation repeats schedule-key binding as defense in
    /// depth, while this facade always pins the single-key session to
    /// `OperatorChannelV1`.
    pub fn narrow_to_causal_authority(
        self,
        policy: &NegotiationPolicyV1,
    ) -> Result<NegotiatedAuthoritySession, AuthoritySessionTransitionError> {
        let activation = self.negotiation.narrow_to_causal_authority(policy)?;
        let inner = private_impl::NegotiatedAuthoritySession::activate(
            self.session,
            activation,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )?;
        Ok(NegotiatedAuthoritySession {
            inner,
            _session_rekey_root: self.session_rekey_root,
        })
    }

    /// Abandon authority activation while keeping the authenticated transport session.
    pub fn into_raw_session(self) -> Session {
        self.session
    }
}

/// Authority-capable single-key envelope session.
///
/// This type can only be reached through authenticated V2 schedule installation
/// followed by local policy narrowing. There is no public constructor accepting
/// an arbitrary raw session, key, activation receipt, or rekey profile.
#[cfg(feature = "handshake")]
pub struct NegotiatedAuthoritySession {
    inner: private_impl::NegotiatedAuthoritySession,
    // Retained privately for the future integrated operator-rekey verifier. It is
    // intentionally not exposed until proposal authentication + key derivation are
    // wired as one operation.
    _session_rekey_root: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "handshake")]
impl NegotiatedAuthoritySession {
    /// Immutable view of the owned raw envelope session.
    pub fn session(&self) -> &Session {
        self.inner.session()
    }

    /// Durable local-policy-bound activation receipt.
    pub fn activation_receipt(&self) -> &AuthorityActivationReceiptV1 {
        self.inner.activation_receipt()
    }

    /// Authenticated selected capability context.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        self.inner.selected_context()
    }

    /// Immutable operator-channel rekey-profile binding.
    pub fn rekey_profile_binding(&self) -> &AuthorityRekeyProfileBindingV1 {
        self.inner.rekey_profile_binding()
    }

    /// Current authority rekey-lineage position.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        self.inner.lineage()
    }

    /// Advance wall-clock session maintenance without exposing mutable raw state.
    pub fn tick(&mut self) {
        self.inner.tick();
    }

    /// Internal evidence-returning verifier used by the public session-bound
    /// online-use API. External negotiated-authority callers should prefer
    /// `verify_session_bound_authority`, whose token borrows this session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_approved_external_action_authority(
        &self,
        request: &ConsentRequest,
        response: &CausalAuthorityResponse,
        revocations: &[ConsentRevocation],
        expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
        expected_responder_pubkey: &[u8; PUBLIC_KEY_LEN],
        now_ms: u64,
    ) -> Result<VerifiedExternalActionAuthority, AuthoritySessionError> {
        self.inner.verify_approved_external_action_authority(
            request,
            response,
            revocations,
            expected_requester_pubkey,
            expected_responder_pubkey,
            now_ms,
        )
    }

    /// Crate-internal staging hook for the future integrated operator-rekey
    /// verifier. External code cannot package an arbitrary key/evidence pair.
    pub(crate) fn apply_verified_rekey(
        &mut self,
        verified: private_impl::VerifiedAuthorityRekey,
    ) -> Result<(), NegotiatedAuthoritySessionError> {
        self.inner.apply_verified_rekey(verified)
    }

    /// Explicitly tear authority state down and recover the unrestricted raw session.
    pub fn into_raw_session(self) -> Session {
        self.inner.into_raw_session()
    }
}

#[cfg(all(test, feature = "handshake"))]
mod tests {
    use super::*;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::handshake_v2_contract::compose_v5_context;
    use crate::negotiated_context::{
        CapabilityOfferEntryV1, negotiate_capabilities,
    };

    const AEAD: [u8; 32] = [0x55; 32];

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn proof() -> AuthenticatedNegotiatedHandshake {
        let host = CapabilityOfferV1::from_entries([
            entry(b"xenia.causal-authority", &[b"draft-04", b"draft-03"]),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let viewer = CapabilityOfferV1::from_entries([
            entry(b"xenia.causal-authority", &[b"draft-04"]),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let negotiation = negotiate_capabilities(&host, &viewer).unwrap();
        let base_v4 = ::core::array::from_fn(|index| index as u8);
        let v5 = compose_v5_context(&base_v4, &negotiation.binding_hash());
        let schedule = SessionKeySchedule {
            aead: AEAD,
            control: [0x31; 32],
            video: [0x32; 32],
            audio: [0x33; 32],
            telemetry: [0x34; 32],
            rekey: [0x35; 32],
            context: [0x36; 32],
            transcript_hash: [0x11; 32],
            host_identity_fingerprint: [0x22; 32],
        };
        AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host, viewer, base_v4, v5, schedule,
        )
        .unwrap()
    }

    #[test]
    fn authenticated_proof_refuses_prekeyed_session() {
        let mut raw = Session::new();
        raw.install_key(AEAD);
        assert!(matches!(
            proof().install_into(raw),
            Err(AuthoritySessionTransitionError::SessionAlreadyKeyed)
        ));
    }

    #[test]
    fn schedule_is_installed_before_local_authority_narrowing() {
        let installed = proof().install_into(Session::new()).unwrap();
        assert!(installed.session.has_key());
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        let authority = installed.narrow_to_causal_authority(&policy).unwrap();
        assert_eq!(
            authority.rekey_profile_binding().profile,
            RekeyTransitionProfileV1::OperatorChannelV1
        );
    }

    #[test]
    fn installed_negotiation_can_be_abandoned_without_authority() {
        let installed = proof().install_into(Session::new()).unwrap();
        let raw = installed.into_raw_session();
        assert!(raw.has_key());
    }

    #[test]
    fn zero_rekey_root_is_rejected_before_public_proof_exists() {
        let host = CapabilityOfferV1::from_entries([
            entry(b"xenia.causal-authority", &[b"draft-04"]),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let viewer = host.clone();
        let negotiation = negotiate_capabilities(&host, &viewer).unwrap();
        let base_v4 = [0x44; 32];
        let v5 = compose_v5_context(&base_v4, &negotiation.binding_hash());
        let schedule = SessionKeySchedule {
            aead: AEAD,
            control: [0x31; 32],
            video: [0x32; 32],
            audio: [0x33; 32],
            telemetry: [0x34; 32],
            rekey: [0; 32],
            context: [0x36; 32],
            transcript_hash: [0x11; 32],
            host_identity_fingerprint: [0x22; 32],
        };
        assert!(matches!(
            AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
                host, viewer, base_v4, v5, schedule,
            ),
            Err(AuthoritySessionTransitionError::ZeroRekeyRoot)
        ));
    }
}
