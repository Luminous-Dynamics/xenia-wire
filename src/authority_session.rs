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

#[allow(dead_code)] // byte-preserved staging implementation hidden by the public facade
#[path = "authority_session_impl.rs"]
mod private_impl;

pub use private_impl::{
    AuthoritySessionError, sign_causal_authority_response_for_session,
    verify_approved_external_action_authority_for_session,
};

#[cfg(feature = "handshake")]
pub use private_impl::NegotiatedAuthoritySessionError;

#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
pub use crate::authority_operator_rekey::OperatorAuthorityRekeyError;

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
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
use crate::authority_rekey_transition_evidence::AuthorityRekeyTransitionEvidenceV1;
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
/// [`Self::install_into`] consumes the proof. The rekey root is retained only in
/// builds that compile the operator-rekey capability.
#[cfg(feature = "handshake")]
pub struct AuthenticatedNegotiatedHandshake {
    inner: private_impl::AuthenticatedNegotiatedHandshake,
    session_aead_key: Zeroizing<[u8; 32]>,
    #[cfg(feature = "operator-rekey")]
    session_rekey_root: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "handshake")]
impl AuthenticatedNegotiatedHandshake {
    /// Construct the public type-state proof from facts already authenticated by
    /// the real V2 cryptographic state machine.
    #[allow(dead_code)] // integration point for the future live V2 state machine
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
        #[cfg(feature = "operator-rekey")]
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
            #[cfg(feature = "operator-rekey")]
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
            #[cfg(feature = "operator-rekey")]
            current_session_key: self.session_aead_key,
            #[cfg(feature = "operator-rekey")]
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
    /// Exact current AEAD key retained only for current-key-only operator rekey
    /// authentication. Generic [`Session::open`] intentionally accepts previous
    /// keys during grace; authority-changing rekey control must not.
    #[cfg(feature = "operator-rekey")]
    current_session_key: Zeroizing<[u8; 32]>,
    /// Authenticated KDF root retained only when this build can perform operator rekey.
    #[cfg(feature = "operator-rekey")]
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
    /// The private implementation performs the existing authenticated-key,
    /// profile and capability checks once. The public facade then takes direct
    /// ownership of the validated session plus immutable evidence so no generic
    /// key-install staging hook remains in the live authority path.
    pub fn narrow_to_causal_authority(
        self,
        policy: &NegotiationPolicyV1,
    ) -> Result<NegotiatedAuthoritySession, AuthoritySessionTransitionError> {
        let activation = self.negotiation.narrow_to_causal_authority(policy)?;
        let validated = private_impl::NegotiatedAuthoritySession::activate(
            self.session,
            activation,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )?;

        let activation = *validated.activation_receipt();
        let selected_context = validated.selected_context().clone();
        let rekey_profile_binding = *validated.rekey_profile_binding();
        let lineage = *validated.lineage();
        let session = validated.into_raw_session();

        Ok(NegotiatedAuthoritySession {
            session,
            activation,
            selected_context,
            rekey_profile_binding,
            lineage,
            #[cfg(feature = "operator-rekey")]
            current_session_key: self.current_session_key,
            #[cfg(feature = "operator-rekey")]
            session_rekey_root: self.session_rekey_root,
        })
    }

    /// Abandon authority activation while keeping the authenticated transport session.
    pub fn into_raw_session(self) -> Session {
        self.session
    }
}

/// Result of accepting one authenticated operator-rekey Proposal while
/// preserving the negotiated authority lineage.
///
/// The Ack is already AEAD-sealed under the new key at sequence zero. The
/// transport owner should send it as opaque bytes; the next envelope sealed by
/// this authority session will use sequence one.
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
pub struct ReceivedOperatorRekey {
    sealed_ack: Vec<u8>,
    transition: AuthorityRekeyTransitionEvidenceV1,
    lineage: AuthorityLineageEpochEvidenceV1,
}

#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
impl ReceivedOperatorRekey {
    /// Sealed new-key Ack ready for the transport owner to send.
    pub fn sealed_ack(&self) -> &[u8] {
        &self.sealed_ack
    }

    /// Consume the receipt without discarding its durable evidence.
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        (self.sealed_ack, self.transition, self.lineage)
    }

    /// Durable public transition evidence for the accepted Proposal.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        &self.transition
    }

    /// Authority lineage after the committed rekey.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        &self.lineage
    }
}

/// Authority-capable single-key envelope session.
///
/// This type can only be reached through authenticated V2 schedule installation
/// followed by local policy narrowing. There is no public constructor accepting
/// an arbitrary raw session, key, activation receipt, rekey profile or lineage.
/// The raw session is never exposed mutably while authority remains live.
#[cfg(feature = "handshake")]
pub struct NegotiatedAuthoritySession {
    session: Session,
    activation: AuthorityActivationReceiptV1,
    selected_context: NegotiatedContextV1,
    rekey_profile_binding: AuthorityRekeyProfileBindingV1,
    lineage: AuthorityLineageEpochEvidenceV1,
    /// Zeroized duplicate of the exact current AEAD key, retained solely to
    /// reject authority-rekey control authenticated by a superseded grace key.
    #[cfg(feature = "operator-rekey")]
    current_session_key: Zeroizing<[u8; 32]>,
    /// Private authenticated operator-rekey KDF root.
    #[cfg(feature = "operator-rekey")]
    session_rekey_root: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "handshake")]
impl NegotiatedAuthoritySession {
    /// Immutable view of the owned raw envelope session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Durable local-policy-bound activation receipt.
    pub fn activation_receipt(&self) -> &AuthorityActivationReceiptV1 {
        &self.activation
    }

    /// Authenticated selected capability context.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        &self.selected_context
    }

    /// Immutable operator-channel rekey-profile binding.
    pub fn rekey_profile_binding(&self) -> &AuthorityRekeyProfileBindingV1 {
        &self.rekey_profile_binding
    }

    /// Current authority rekey-lineage position.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        &self.lineage
    }

    /// Advance wall-clock session maintenance without exposing mutable raw state.
    pub fn tick(&mut self) {
        self.session.tick();
    }

    /// Authenticate and accept one sealed operator-channel rekey Proposal.
    ///
    /// The caller supplies only the opaque old-key envelope. This method owns
    /// current-key-only authentication, live replay acceptance, Proposal
    /// decoding, epoch/hash/profile/lineage verification, replacement-key
    /// derivation from the private authenticated rekey root, sequence-zero Ack
    /// preparation, key installation and lineage advancement. No public API
    /// accepts a decoded Proposal or caller-supplied replacement key.
    ///
    /// On rejection, the live key, private current-key copy, outbound nonce
    /// counter, activation and authority lineage remain unchanged. An envelope
    /// that authenticates under the exact current key may still consume receive
    /// replay-window state before a later semantic check rejects it; that is
    /// intentional anti-replay behavior.
    #[cfg(feature = "operator-rekey")]
    pub fn receive_operator_rekey_proposal(
        &mut self,
        envelope: &[u8],
    ) -> Result<ReceivedOperatorRekey, OperatorAuthorityRekeyError> {
        let accepted = crate::authority_operator_rekey::receive_and_commit_operator_rekey(
            &mut self.session,
            &mut self.current_session_key,
            &mut self.lineage,
            &self.activation,
            &self.selected_context,
            &self.rekey_profile_binding,
            &self.session_rekey_root,
            envelope,
        )?;
        Ok(ReceivedOperatorRekey {
            sealed_ack: accepted.sealed_ack,
            transition: accepted.transition,
            lineage: accepted.lineage,
        })
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
        verify_approved_external_action_authority_for_session(
            &self.session,
            request,
            response,
            revocations,
            expected_requester_pubkey,
            expected_responder_pubkey,
            now_ms,
        )
    }

    /// Explicitly tear authority state down and recover the unrestricted raw session.
    pub fn into_raw_session(self) -> Session {
        self.session
    }
}

#[cfg(all(test, feature = "handshake"))]
#[path = "authority_session_tests.rs"]
mod tests;