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
//!
//! With `operator-rekey` enabled, [`NegotiatedAuthoritySession`] also owns the
//! complete receiver-side authority-preserving rekey transaction. Public callers
//! submit sealed Proposal envelope bytes only; they cannot supply replacement
//! keys or detached claims that a decoded Proposal was authenticated.

#[allow(dead_code)] // byte-preserved staging implementation hidden by the public facade
#[path = "authority_session_impl.rs"]
mod private_impl;

pub use private_impl::{
    AuthoritySessionError, sign_causal_authority_response_for_session,
    verify_approved_external_action_authority_for_session,
};

#[cfg(feature = "handshake")]
pub use private_impl::NegotiatedAuthoritySessionError;

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
use crate::authority_rekey_profile_binding::{
    AuthorityRekeyProfileBindingError, advance_profile_bound_lineage_after_verified_transition,
};
#[cfg(feature = "handshake")]
use crate::authority_rekey_transition_evidence::RekeyTransitionProfileV1;
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
use crate::authority_rekey_transition_evidence::{
    AuthorityRekeyTransitionEvidenceError, AuthorityRekeyTransitionEvidenceV1,
    RekeyTransitionReasonV1,
};
#[cfg(feature = "handshake")]
use crate::consent::{ConsentRequest, ConsentRevocation, PUBLIC_KEY_LEN};
#[cfg(feature = "handshake")]
use crate::handshake::SessionKeySchedule;
#[cfg(feature = "handshake")]
use crate::negotiated_context::{CapabilityOfferV1, NegotiatedContextV1};
#[cfg(feature = "handshake")]
use crate::negotiation_policy::NegotiationPolicyV1;
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
use crate::operator_rekey::{
    OperatorRekeyMessage, OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY,
    derive_operator_rekey_key, verify_proposal_epoch_hash,
};
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
use crate::{WireError, envelope_payload_type};
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
use std::time::Duration;
#[cfg(feature = "handshake")]
use zeroize::Zeroizing;

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
        let current_session_aead_key = Zeroizing::new(*self.session_aead_key);
        session.install_key(*self.session_aead_key);
        Ok(InstalledNegotiatedSession {
            session,
            negotiation: self.inner,
            session_rekey_root: self.session_rekey_root,
            current_session_aead_key,
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
    current_session_aead_key: Zeroizing<[u8; 32]>,
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
    /// The private implementation performs the initial schedule-key/profile
    /// binding as defense in depth. The validated raw session and public evidence
    /// are then moved into this facade so integrated rekey can own the complete
    /// live transition without exposing mutable raw-session access.
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
        let profile_binding = *validated.rekey_profile_binding();
        let lineage = *validated.lineage();
        let session = validated.into_raw_session();

        Ok(NegotiatedAuthoritySession {
            session,
            activation,
            selected_context,
            profile_binding,
            lineage,
            session_rekey_root: self.session_rekey_root,
            current_session_aead_key: self.current_session_aead_key,
        })
    }

    /// Abandon authority activation while keeping the authenticated transport session.
    pub fn into_raw_session(self) -> Session {
        self.session
    }
}

/// Result of one accepted receiver-side authority-preserving operator rekey.
///
/// The replacement key is deliberately absent. The caller receives only the
/// sealed Ack that must be sent to the initiator and durable public evidence for
/// the transition/advanced authority lineage.
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityOperatorRekeyAcceptance {
    sealed_ack: Vec<u8>,
    transition: AuthorityRekeyTransitionEvidenceV1,
    lineage: AuthorityLineageEpochEvidenceV1,
}

#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
impl AuthorityOperatorRekeyAcceptance {
    /// Ack envelope sealed as sequence zero under the accepted new epoch key.
    pub fn sealed_ack(&self) -> &[u8] {
        &self.sealed_ack
    }

    /// Durable public evidence for the accepted operator-channel transition.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        &self.transition
    }

    /// Durable public authority-lineage position after the accepted transition.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        &self.lineage
    }

    /// Consume the result into transport bytes plus durable evidence.
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        (self.sealed_ack, self.transition, self.lineage)
    }
}

/// Failure while processing a sealed receiver-side authority operator rekey.
#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
#[derive(Debug, thiserror::Error)]
pub enum AuthorityOperatorRekeyError {
    /// The cleartext nonce route is not the operator-rekey payload type.
    #[error("authority operator rekey envelope has the wrong payload type")]
    WrongPayloadType,
    /// The envelope was not authenticated by the exact current authority key.
    /// A still-valid previous/grace key is intentionally insufficient.
    #[error("authority operator rekey proposal is not authenticated by the exact current key")]
    CurrentKeyAuthenticationFailed,
    /// The handler accepts inbound Proposal messages only.
    #[error("authority operator rekey handler requires Proposal, not Ack")]
    UnexpectedAck,
    /// The current authority epoch cannot be incremented.
    #[error("authority operator rekey epoch overflow")]
    EpochOverflow,
    /// Proposal epoch is not exactly the current authority epoch plus one.
    #[error("authority operator rekey proposal is not the next contiguous epoch")]
    NonContiguousEpoch,
    /// Proposal is rooted in a different authenticated handshake transcript.
    #[error("authority operator rekey base transcript does not match activation")]
    BaseTranscriptMismatch,
    /// Proposal does not point to the current local authority chain head.
    #[error("authority operator rekey previous epoch hash does not match local lineage")]
    PreviousEpochHashMismatch,
    /// The operator protocol verifier and authority evidence mirror disagreed.
    #[error("authority operator rekey verified epoch hash disagrees with transition evidence")]
    TransitionHashMismatch,
    /// A derived replacement key must create a genuinely new cryptographic key domain.
    #[error("authority operator rekey derived the current AEAD key again")]
    DerivedKeyDidNotChange,
    /// Wire open/decode/encode/seal failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Public transition evidence construction/validation failed.
    #[error(transparent)]
    Transition(#[from] AuthorityRekeyTransitionEvidenceError),
    /// Profile/capability/lineage binding rejected the transition.
    #[error(transparent)]
    Profile(#[from] AuthorityRekeyProfileBindingError),
}

/// Authority-capable single-key envelope session.
///
/// This type can only be reached through authenticated V2 schedule installation
/// followed by local policy narrowing. There is no public constructor accepting
/// an arbitrary raw session, key, activation receipt, rekey root, or rekey
/// profile. Mutable raw-session access is never exposed while authority is live.
#[cfg(feature = "handshake")]
pub struct NegotiatedAuthoritySession {
    session: Session,
    activation: AuthorityActivationReceiptV1,
    selected_context: NegotiatedContextV1,
    profile_binding: AuthorityRekeyProfileBindingV1,
    lineage: AuthorityLineageEpochEvidenceV1,
    session_rekey_root: Zeroizing<[u8; 32]>,
    // Exact current AEAD key retained solely for the current-key-only authority
    // rekey precheck. This intentionally duplicates the live Session's key in a
    // second Zeroizing owner; issue #38 tracks reducing raw key-copy exposure.
    current_session_aead_key: Zeroizing<[u8; 32]>,
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
        &self.profile_binding
    }

    /// Current authority rekey-lineage position.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        &self.lineage
    }

    /// Advance wall-clock session maintenance without exposing mutable raw state.
    pub fn tick(&mut self) {
        self.session.tick();
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

    /// Accept one sealed, authenticated **receiver-side** operator rekey Proposal.
    ///
    /// This is the only public authority-preserving rekey mutation. It consumes
    /// sealed bytes, authenticates them against the exact current key, consumes
    /// the live replay slot, verifies Proposal/hash/epoch/activation/profile
    /// continuity, derives the replacement key from the private authenticated
    /// rekey root, precomputes next lineage, and pre-seals the Ack before any
    /// live key/lineage mutation occurs.
    ///
    /// After every fallible step succeeds, the live key is replaced, sequence
    /// zero is reserved for the already-presealed Ack, and the precomputed
    /// lineage is assigned using only infallible state updates. Authenticated
    /// envelopes that later fail semantic checks intentionally remain consumed
    /// by the replay window; authority/key/lineage state does not advance.
    ///
    /// The initiator side is deliberately not represented by this method. Wire
    /// does not own transport delivery, so proposal-send/commit/Ack lifecycle
    /// must be owned by xenia-peer or another transport-aware layer.
    #[cfg(feature = "operator-rekey")]
    pub fn accept_operator_rekey_proposal(
        &mut self,
        sealed_proposal: &[u8],
    ) -> Result<AuthorityOperatorRekeyAcceptance, AuthorityOperatorRekeyError> {
        if envelope_payload_type(sealed_proposal) != Some(PAYLOAD_TYPE_OPERATOR_REKEY) {
            return Err(AuthorityOperatorRekeyError::WrongPayloadType);
        }

        // Authority rekey must authenticate under the exact current key. Generic
        // Session::open intentionally accepts previous keys during grace, which
        // is correct for in-flight application data but too permissive for a new
        // authority transition. This temporary session has no previous keys and
        // never affects live replay state.
        let mut current_only = Session::with_source_id(*self.session.source_id(), self.session.epoch())
            .with_rekey_grace(Duration::ZERO);
        current_only.install_key(*self.current_session_aead_key);
        current_only
            .open(sealed_proposal)
            .map_err(|_| AuthorityOperatorRekeyError::CurrentKeyAuthenticationFailed)?;

        // The live open is still required: it owns the real replay window. Once
        // an envelope authenticates here, semantic rejection below does not roll
        // replay acceptance back.
        let plaintext = self.session.open(sealed_proposal)?;
        let message = OperatorRekeyMessage::decode(&plaintext)?;
        let OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        } = message
        else {
            return Err(AuthorityOperatorRekeyError::UnexpectedAck);
        };

        let verified_epoch_hash = verify_proposal_epoch_hash(
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        )?;

        let expected_epoch = self
            .lineage
            .key_epoch
            .checked_add(1)
            .ok_or(AuthorityOperatorRekeyError::EpochOverflow)?;
        if key_epoch != expected_epoch {
            return Err(AuthorityOperatorRekeyError::NonContiguousEpoch);
        }
        if base_transcript_hash != self.activation.handshake_transcript_hash {
            return Err(AuthorityOperatorRekeyError::BaseTranscriptMismatch);
        }
        if previous_epoch_hash != self.lineage.current_epoch_hash {
            return Err(AuthorityOperatorRekeyError::PreviousEpochHashMismatch);
        }

        let transition_reason = match reason {
            OperatorRekeyReason::Interval => RekeyTransitionReasonV1::OperatorInterval,
            OperatorRekeyReason::Manual => RekeyTransitionReasonV1::OperatorManual,
        };
        let transition = AuthorityRekeyTransitionEvidenceV1::operator(
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            transition_reason,
        )?;
        if transition.epoch_hash != verified_epoch_hash {
            return Err(AuthorityOperatorRekeyError::TransitionHashMismatch);
        }

        let next_lineage = advance_profile_bound_lineage_after_verified_transition(
            &self.lineage,
            &self.activation,
            &self.selected_context,
            &self.profile_binding,
            &transition,
        )?;

        let new_key = Zeroizing::new(derive_operator_rekey_key(
            &self.session_rekey_root,
            &verified_epoch_hash,
        ));
        if ct_eq_32(&new_key, &self.current_session_aead_key) {
            return Err(AuthorityOperatorRekeyError::DerivedKeyDidNotChange);
        }

        let ack = OperatorRekeyMessage::Ack {
            key_epoch,
            epoch_hash: verified_epoch_hash,
        };
        let ack_plaintext = ack.encode()?;

        // Prepare sequence-zero Ack under the proposed new key using the exact
        // live nonce-domain metadata. Every operation from here until live commit
        // is still fallible and therefore happens before live state mutation.
        let mut prepared_sender =
            Session::with_source_id(*self.session.source_id(), self.session.epoch())
                .with_rekey_grace(Duration::ZERO);
        prepared_sender.install_key(*new_key);
        let sealed_ack = prepared_sender.seal(&ack_plaintext, PAYLOAD_TYPE_OPERATOR_REKEY)?;
        debug_assert_eq!(prepared_sender.nonce_counter(), 1);

        // Commit boundary: all remaining operations are infallible under the
        // current Session contract. install_key() creates the new key epoch,
        // next_nonce() reserves sequence zero for the already-presealed Ack, and
        // lineage/key-copy assignment cannot return an error.
        self.session.install_key(*new_key);
        let reserved = self.session.next_nonce();
        debug_assert_eq!(reserved, 0);
        self.lineage = next_lineage;
        self.current_session_aead_key = new_key;

        Ok(AuthorityOperatorRekeyAcceptance {
            sealed_ack,
            transition,
            lineage: next_lineage,
        })
    }

    /// Explicitly tear authority state down and recover the unrestricted raw session.
    pub fn into_raw_session(self) -> Session {
        self.session
    }
}

#[cfg(all(feature = "handshake", feature = "operator-rekey"))]
#[inline]
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for index in 0..32 {
        diff |= a[index] ^ b[index];
    }
    diff == 0
}

#[cfg(all(test, feature = "handshake"))]
mod tests {
    use super::*;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::handshake_v2_contract::compose_v5_context;
    use crate::negotiated_context::{CapabilityOfferEntryV1, negotiate_capabilities};

    const AEAD: [u8; 32] = [0x55; 32];
    const REKEY_ROOT: [u8; 32] = [0x35; 32];
    const SOURCE_ID: [u8; 8] = *b"authop01";
    const SESSION_EPOCH: u8 = 0x44;

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
            rekey: REKEY_ROOT,
            context: [0x36; 32],
            transcript_hash: [0x11; 32],
            host_identity_fingerprint: [0x22; 32],
        };
        AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host, viewer, base_v4, v5, schedule,
        )
        .unwrap()
    }

    fn authority() -> NegotiatedAuthoritySession {
        let installed = proof()
            .install_into(Session::with_source_id(SOURCE_ID, SESSION_EPOCH))
            .unwrap();
        let policy =
            NegotiationPolicyV1::minimum_required([causal_authority_draft04_capability()]).unwrap();
        installed.narrow_to_causal_authority(&policy).unwrap()
    }

    #[cfg(feature = "operator-rekey")]
    fn seal_operator_message(key: [u8; 32], message: &OperatorRekeyMessage) -> Vec<u8> {
        let mut sender = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
        sender.install_key(key);
        sender
            .seal(&message.encode().unwrap(), PAYLOAD_TYPE_OPERATOR_REKEY)
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
        let policy =
            NegotiationPolicyV1::minimum_required([causal_authority_draft04_capability()]).unwrap();
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

    #[cfg(feature = "operator-rekey")]
    #[test]
    fn sealed_receiver_rekey_commits_once_and_reserves_ack_nonce_zero() {
        let mut authority = authority();
        let before_lineage = *authority.lineage();
        let before_fp = authority.session().session_fingerprint(7).unwrap();

        let proposal = crate::operator_rekey::propose(
            1,
            [0x11; 32],
            [0x11; 32],
            OperatorRekeyReason::Manual,
        )
        .unwrap();
        let sealed = seal_operator_message(AEAD, &proposal);
        let accepted = authority.accept_operator_rekey_proposal(&sealed).unwrap();

        assert_eq!(before_lineage.key_epoch, 0);
        assert_eq!(accepted.transition().key_epoch, 1);
        assert_eq!(accepted.lineage().key_epoch, 1);
        assert_eq!(authority.lineage(), accepted.lineage());
        assert_eq!(authority.session().nonce_counter(), 1);

        let new_key = derive_operator_rekey_key(REKEY_ROOT.as_ref(), &accepted.transition().epoch_hash);
        let mut ack_receiver = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
        ack_receiver.install_key(new_key);
        let ack_plaintext = ack_receiver.open(accepted.sealed_ack()).unwrap();
        assert_eq!(
            OperatorRekeyMessage::decode(&ack_plaintext).unwrap(),
            OperatorRekeyMessage::Ack {
                key_epoch: 1,
                epoch_hash: accepted.transition().epoch_hash,
            }
        );

        let after_fp = authority.session().session_fingerprint(7).unwrap();
        assert_ne!(before_fp, after_fp);
        let mut expected = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
        expected.install_key(new_key);
        assert_eq!(after_fp, expected.session_fingerprint(7).unwrap());

        let mut raw = authority.into_raw_session();
        let next = raw.seal(b"next operator control", PAYLOAD_TYPE_OPERATOR_REKEY).unwrap();
        assert_eq!(&next[8..12], &[1, 0, 0, 0]);
    }

    #[cfg(feature = "operator-rekey")]
    #[test]
    fn authenticated_semantic_rejection_consumes_replay_but_not_authority_state() {
        let mut authority = authority();
        let before_lineage = *authority.lineage();
        let before_fp = authority.session().session_fingerprint(9).unwrap();
        let ack = OperatorRekeyMessage::Ack {
            key_epoch: 1,
            epoch_hash: [0x77; 32],
        };
        let sealed = seal_operator_message(AEAD, &ack);

        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed),
            Err(AuthorityOperatorRekeyError::UnexpectedAck)
        ));
        assert_eq!(*authority.lineage(), before_lineage);
        assert_eq!(authority.session().session_fingerprint(9).unwrap(), before_fp);
        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed),
            Err(AuthorityOperatorRekeyError::Wire(WireError::OpenFailed))
        ));
    }

    #[cfg(feature = "operator-rekey")]
    #[test]
    fn wrong_route_fails_before_live_replay_or_authority_mutation() {
        let mut authority = authority();
        let before = *authority.lineage();
        let proposal = crate::operator_rekey::propose(
            1,
            [0x11; 32],
            [0x11; 32],
            OperatorRekeyReason::Interval,
        )
        .unwrap();
        let mut sender = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
        sender.install_key(AEAD);
        let sealed = sender
            .seal(
                &proposal.encode().unwrap(),
                crate::payload_types::PAYLOAD_TYPE_APPLICATION_MIN,
            )
            .unwrap();

        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed),
            Err(AuthorityOperatorRekeyError::WrongPayloadType)
        ));
        assert_eq!(*authority.lineage(), before);
    }

    #[cfg(feature = "operator-rekey")]
    #[test]
    fn previous_grace_key_cannot_drive_a_fresh_authority_rekey() {
        let mut authority = authority();
        let first = crate::operator_rekey::propose(
            1,
            [0x11; 32],
            [0x11; 32],
            OperatorRekeyReason::Manual,
        )
        .unwrap();
        let first_sealed = seal_operator_message(AEAD, &first);
        let first_accepted = authority
            .accept_operator_rekey_proposal(&first_sealed)
            .unwrap();
        let epoch1_hash = first_accepted.transition().epoch_hash;
        let epoch1_key = derive_operator_rekey_key(REKEY_ROOT.as_ref(), &epoch1_hash);

        let second = crate::operator_rekey::propose(
            2,
            [0x11; 32],
            epoch1_hash,
            OperatorRekeyReason::Interval,
        )
        .unwrap();
        let sealed_under_previous = seal_operator_message(AEAD, &second);
        let before_lineage = *authority.lineage();
        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed_under_previous),
            Err(AuthorityOperatorRekeyError::CurrentKeyAuthenticationFailed)
        ));
        assert_eq!(*authority.lineage(), before_lineage);

        // The failed current-key-only precheck must happen before the live replay
        // window. Once authority is explicitly torn down, the same old-key
        // envelope is still accepted by the generic Session through grace.
        let mut raw = authority.into_raw_session();
        let opened = raw.open(&sealed_under_previous).unwrap();
        assert_eq!(OperatorRekeyMessage::decode(&opened).unwrap(), second);

        // Sanity: the same proposal under the exact current epoch-1 key is valid
        // cryptographically. A separate authority instance covers semantic commit.
        let mut authority = authority();
        let first_sealed = seal_operator_message(AEAD, &first);
        authority
            .accept_operator_rekey_proposal(&first_sealed)
            .unwrap();
        let sealed_under_current = seal_operator_message(epoch1_key, &second);
        let second_accepted = authority
            .accept_operator_rekey_proposal(&sealed_under_current)
            .unwrap();
        assert_eq!(second_accepted.lineage().key_epoch, 2);
    }
}
