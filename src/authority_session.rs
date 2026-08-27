// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Rekey-aware safe-path helpers and type-state contracts for exact authority.
//!
//! The low-level authority verifier accepts an expected session fingerprint so
//! offline/transcript verifiers can supply independently authenticated context.
//! Live Xenia applications should normally use this module instead: it asks the
//! [`crate::Session`] to authenticate the request against the current session key
//! or any still-valid previous key in the rekey grace window, then delegates to
//! the exact request-bound authority verifier.
//!
//! With `handshake` enabled this module also stages the ownership boundary for
//! dynamically negotiated authority. The important invariant is that a raw
//! [`crate::Session`] remains a generic transport primitive whose
//! [`crate::Session::install_key`] method is intentionally unrestricted, while a
//! [`NegotiatedAuthoritySession`] *owns* that raw session and exposes no mutable
//! `Session` reference. Arbitrary key replacement is therefore possible only by
//! consuming the authority wrapper via [`NegotiatedAuthoritySession::into_raw_session`],
//! which tears down authority state.
//!
//! The negotiated proof constructors below are crate-private until the real V2
//! handshake state machine exists. Safe external Rust code therefore cannot
//! manufacture authenticated negotiation or verified-rekey tokens from hashes.

#![cfg(feature = "causal-authority")]

use ed25519_dalek::SigningKey;

use crate::Session;
use crate::authority::{
    CausalAuthorityResponse, ExternalAuthorityError, VerifiedExternalActionAuthority,
    verify_approved_external_action_authority,
};
use crate::consent::{ConsentRequest, ConsentRevocation, PUBLIC_KEY_LEN};

#[cfg(feature = "handshake")]
use zeroize::Zeroizing;
#[cfg(feature = "handshake")]
use crate::authority_activation_evidence::{
    AuthorityActivationEvidenceError, AuthorityActivationReceiptV1,
    derive_authority_activation_receipt,
};
#[cfg(feature = "handshake")]
use crate::authority_lineage_epoch_evidence::{
    AuthorityLineageEpochEvidenceError, AuthorityLineageEpochEvidenceV1,
};
#[cfg(feature = "handshake")]
use crate::authority_rekey_profile_binding::{
    AuthorityRekeyProfileBindingError, AuthorityRekeyProfileBindingV1,
    advance_profile_bound_lineage_after_verified_transition,
};
#[cfg(feature = "handshake")]
use crate::authority_rekey_transition_evidence::{
    AuthorityRekeyTransitionEvidenceV1, RekeyTransitionProfileV1,
};
#[cfg(feature = "handshake")]
use crate::handshake_v2_contract::compose_v5_context;
#[cfg(feature = "handshake")]
use crate::negotiated_context::{
    CapabilityOfferV1, NegotiatedContextError, NegotiatedContextV1, negotiate_capabilities,
};
#[cfg(feature = "handshake")]
use crate::negotiation_policy::NegotiationPolicyV1;

/// Failures specific to binding exact authority to a live Xenia session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthoritySessionError {
    /// The signed request is not authentic for the expected requester in this
    /// session's current or still-valid previous key epoch.
    #[error("causal authority request is not authenticated for this Xenia session")]
    RequestNotBoundToSession,
    /// Exact-authority semantic or cryptographic verification failed.
    #[error(transparent)]
    Authority(#[from] ExternalAuthorityError),
}

/// Sign a bound authority response only after authenticating the request against
/// this live Xenia session.
///
/// `Session::verify_consent_request` probes both the current session key and all
/// still-valid previous keys in the rekey grace window. A request signed moments
/// before a rekey can therefore still be approved safely after the rekey, while a
/// request from an unrelated session fails closed.
#[allow(clippy::too_many_arguments)]
pub fn sign_causal_authority_response_for_session(
    session: &Session,
    request: &ConsentRequest,
    expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
    approved: bool,
    issued_at_ms: u64,
    reason: impl Into<String>,
    responder_signing_key: &SigningKey,
) -> Result<CausalAuthorityResponse, AuthoritySessionError> {
    if !session.verify_consent_request(request, Some(expected_requester_pubkey)) {
        return Err(AuthoritySessionError::RequestNotBoundToSession);
    }

    Ok(CausalAuthorityResponse::sign_for_request(
        request,
        approved,
        issued_at_ms,
        reason,
        responder_signing_key,
    )?)
}

/// Verify exact external authority against a live Xenia session.
///
/// This is the recommended online verification path. The session first proves
/// that the request fingerprint belongs to its current or rekey-grace key
/// material. Only after that proof succeeds is the request's embedded
/// fingerprint promoted to the `expected_session_fingerprint` supplied to the
/// lower-level exact verifier.
///
/// Offline evidence systems that independently authenticate a transcript may use
/// `authority::verify_approved_external_action_authority` directly instead.
#[allow(clippy::too_many_arguments)]
pub fn verify_approved_external_action_authority_for_session(
    session: &Session,
    request: &ConsentRequest,
    response: &CausalAuthorityResponse,
    revocations: &[ConsentRevocation],
    expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
    expected_responder_pubkey: &[u8; PUBLIC_KEY_LEN],
    now_ms: u64,
) -> Result<VerifiedExternalActionAuthority, AuthoritySessionError> {
    if !session.verify_consent_request(request, Some(expected_requester_pubkey)) {
        return Err(AuthoritySessionError::RequestNotBoundToSession);
    }

    Ok(verify_approved_external_action_authority(
        request,
        response,
        revocations,
        expected_requester_pubkey,
        expected_responder_pubkey,
        &request.core.session_fingerprint,
        now_ms,
    )?)
}

/// Authenticated facts produced by a completed dynamic V2 handshake.
///
/// This type intentionally has no public constructor and is not serializable.
/// The future V2 handshake state machine may construct it only *after* both
/// transcript signature suites verify and both peers' canonical offers have
/// deterministically produced the observed V5 context.
#[cfg(feature = "handshake")]
pub struct AuthenticatedNegotiatedHandshake {
    host_offer: CapabilityOfferV1,
    viewer_offer: CapabilityOfferV1,
    selected_context: NegotiatedContextV1,
    base_v4_context_hash: [u8; 32],
    final_v5_context_hash: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    host_identity_fingerprint: [u8; 32],
}

#[cfg(feature = "handshake")]
impl AuthenticatedNegotiatedHandshake {
    /// Construct authenticated negotiation state from facts already verified by
    /// the real V2 cryptographic state machine.
    ///
    /// Kept crate-private so no external caller can turn hashes into a proof.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_v2_parts(
        host_offer: CapabilityOfferV1,
        viewer_offer: CapabilityOfferV1,
        base_v4_context_hash: [u8; 32],
        observed_final_v5_context_hash: [u8; 32],
        handshake_transcript_hash: [u8; 32],
        host_identity_fingerprint: [u8; 32],
    ) -> Result<Self, NegotiatedAuthoritySessionError> {
        require_nonzero(base_v4_context_hash)?;
        require_nonzero(observed_final_v5_context_hash)?;
        require_nonzero(handshake_transcript_hash)?;
        require_nonzero(host_identity_fingerprint)?;

        let negotiation = negotiate_capabilities(&host_offer, &viewer_offer)?;
        let expected_v5 = compose_v5_context(&base_v4_context_hash, &negotiation.binding_hash());
        if observed_final_v5_context_hash != expected_v5 {
            return Err(NegotiatedAuthoritySessionError::NegotiatedV5Mismatch);
        }

        Ok(Self {
            host_offer,
            viewer_offer,
            selected_context: negotiation.selected_context().clone(),
            base_v4_context_hash,
            final_v5_context_hash: expected_v5,
            handshake_transcript_hash,
            host_identity_fingerprint,
        })
    }

    /// Authenticated selected capability context.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        &self.selected_context
    }

    /// Authenticated V5 session-context commitment.
    pub fn final_v5_context_hash(&self) -> &[u8; 32] {
        &self.final_v5_context_hash
    }

    /// Narrow authenticated negotiation into local causal-authority activation.
    ///
    /// This is a separate consuming step because peer-authenticated negotiation
    /// does not itself imply local acceptance. The supplied policy is evaluated
    /// again while deriving the durable activation receipt.
    pub fn narrow_to_causal_authority(
        self,
        policy: &NegotiationPolicyV1,
    ) -> Result<AuthenticatedAuthorityActivation, NegotiatedAuthoritySessionError> {
        let receipt = derive_authority_activation_receipt(
            &self.host_offer,
            &self.viewer_offer,
            self.base_v4_context_hash,
            self.handshake_transcript_hash,
            self.host_identity_fingerprint,
            policy,
        )?;
        if receipt.final_v5_context_hash != self.final_v5_context_hash
            || receipt.selected_context_hash != self.selected_context.hash()
        {
            return Err(NegotiatedAuthoritySessionError::ActivationDoesNotMatchHandshake);
        }
        Ok(AuthenticatedAuthorityActivation {
            receipt,
            selected_context: self.selected_context,
        })
    }
}

/// Authenticated negotiated authority after local policy narrowing.
///
/// No public constructor exists. Safe callers obtain this only by consuming an
/// [`AuthenticatedNegotiatedHandshake`] through local policy evaluation.
#[cfg(feature = "handshake")]
pub struct AuthenticatedAuthorityActivation {
    receipt: AuthorityActivationReceiptV1,
    selected_context: NegotiatedContextV1,
}

#[cfg(feature = "handshake")]
impl AuthenticatedAuthorityActivation {
    /// Durable policy-bound activation receipt.
    pub fn receipt(&self) -> &AuthorityActivationReceiptV1 {
        &self.receipt
    }

    /// Authenticated selected capability context used by this activation.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        &self.selected_context
    }
}

/// Rekey result produced only by an existing cryptographic rekey verifier.
///
/// The constructor is crate-private. Public code can inspect the resulting
/// transition evidence but cannot manufacture a token and thereby ask an
/// authority session to install an arbitrary replacement key.
#[cfg(feature = "handshake")]
pub struct VerifiedAuthorityRekey {
    transition: AuthorityRekeyTransitionEvidenceV1,
    new_key: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "handshake")]
impl VerifiedAuthorityRekey {
    /// Package the key and public transition evidence after cryptographic rekey
    /// verification has succeeded.
    pub(crate) fn from_verified_transition(
        transition: AuthorityRekeyTransitionEvidenceV1,
        new_key: [u8; 32],
    ) -> Result<Self, NegotiatedAuthoritySessionError> {
        if new_key.iter().all(|byte| *byte == 0) {
            return Err(NegotiatedAuthoritySessionError::ZeroRekeyKey);
        }
        transition.validate()?;
        Ok(Self {
            transition,
            new_key: Zeroizing::new(new_key),
        })
    }

    /// Public evidence describing the cryptographically verified transition.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        &self.transition
    }
}

/// Authority-capable session that owns the underlying raw [`Session`].
///
/// Deliberately does not implement `Deref`, `AsMut<Session>`, or expose a
/// `&mut Session`; callers therefore cannot invoke unrestricted
/// [`Session::install_key`] while retaining authority state. Leaving this type
/// via [`Self::into_raw_session`] consumes the wrapper and tears authority down.
#[cfg(feature = "handshake")]
pub struct NegotiatedAuthoritySession {
    session: Session,
    activation: AuthorityActivationReceiptV1,
    selected_context: NegotiatedContextV1,
    profile_binding: AuthorityRekeyProfileBindingV1,
    lineage: AuthorityLineageEpochEvidenceV1,
}

#[cfg(feature = "handshake")]
impl NegotiatedAuthoritySession {
    /// Activate authority on an already-keyed raw session using an authenticated,
    /// locally accepted V2 authority proof.
    pub fn activate(
        session: Session,
        activation: AuthenticatedAuthorityActivation,
        rekey_profile: RekeyTransitionProfileV1,
    ) -> Result<Self, NegotiatedAuthoritySessionError> {
        if !session.has_key() {
            return Err(NegotiatedAuthoritySessionError::SessionHasNoKey);
        }
        let profile_binding = AuthorityRekeyProfileBindingV1::new(
            &activation.receipt,
            &activation.selected_context,
            rekey_profile,
        )?;
        let lineage = AuthorityLineageEpochEvidenceV1::initial(&activation.receipt)?;
        Ok(Self {
            session,
            activation: activation.receipt,
            selected_context: activation.selected_context,
            profile_binding,
            lineage,
        })
    }

    /// Immutable raw-session view for observability and fingerprint verification.
    ///
    /// No mutable view is exposed because that would reopen unrestricted key
    /// installation while authority state remains live.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Current durable activation receipt.
    pub fn activation_receipt(&self) -> &AuthorityActivationReceiptV1 {
        &self.activation
    }

    /// Authenticated selected capability context.
    pub fn selected_context(&self) -> &NegotiatedContextV1 {
        &self.selected_context
    }

    /// Immutable rekey-profile binding for this activation.
    pub fn rekey_profile_binding(&self) -> &AuthorityRekeyProfileBindingV1 {
        &self.profile_binding
    }

    /// Current authority rekey-lineage position.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        &self.lineage
    }

    /// Advance wall-clock maintenance without exposing mutable raw-session access.
    pub fn tick(&mut self) {
        self.session.tick();
    }

    /// Verify exact request-bound authority through the owned live session.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_approved_external_action_authority(
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

    /// Apply a replacement key only when accompanied by an unforgeable verified
    /// rekey token from Xenia's existing cryptographic rekey path.
    ///
    /// Evidence/profile/continuity checks complete *before* key mutation. A
    /// rejected transition therefore leaves both the raw key and lineage state
    /// unchanged.
    pub fn apply_verified_rekey(
        &mut self,
        verified: VerifiedAuthorityRekey,
    ) -> Result<(), NegotiatedAuthoritySessionError> {
        let next_lineage = advance_profile_bound_lineage_after_verified_transition(
            &self.lineage,
            &self.activation,
            &self.selected_context,
            &self.profile_binding,
            &verified.transition,
        )?;
        self.session.install_key(*verified.new_key);
        self.lineage = next_lineage;
        Ok(())
    }

    /// Explicitly abandon authority state and recover the generic raw session.
    ///
    /// After this consuming transition the caller may use unrestricted
    /// [`Session::install_key`], but there is no authority wrapper left to retain
    /// or accidentally reuse the previous activation/lineage proof.
    pub fn into_raw_session(self) -> Session {
        self.session
    }
}

/// Failure while constructing or advancing negotiated authority session state.
#[cfg(feature = "handshake")]
#[derive(Debug, thiserror::Error)]
pub enum NegotiatedAuthoritySessionError {
    /// Canonical host/viewer offer negotiation failed.
    #[error(transparent)]
    Negotiation(#[from] NegotiatedContextError),
    /// Durable authority activation derivation or local policy evaluation failed.
    #[error(transparent)]
    Activation(#[from] AuthorityActivationEvidenceError),
    /// Rekey-profile/capability/lineage validation failed.
    #[error(transparent)]
    RekeyProfile(#[from] AuthorityRekeyProfileBindingError),
    /// Initial lineage evidence was malformed.
    #[error(transparent)]
    Lineage(#[from] AuthorityLineageEpochEvidenceError),
    /// Public transition evidence was malformed before it reached profile checks.
    #[error(transparent)]
    RekeyTransition(#[from] crate::authority_rekey_transition_evidence::AuthorityRekeyTransitionEvidenceError),
    /// The V5 observed in the authenticated handshake does not equal deterministic
    /// recomputation from V4 plus both canonical peer offers.
    #[error("authenticated V2 V5 context does not match deterministic negotiation")]
    NegotiatedV5Mismatch,
    /// Local activation derivation disagreed with the authenticated handshake.
    #[error("authority activation does not match authenticated V2 handshake facts")]
    ActivationDoesNotMatchHandshake,
    /// A required cryptographic commitment was the all-zero sentinel.
    #[error("authenticated negotiated handshake contains an all-zero commitment")]
    ZeroCommitment,
    /// Authority cannot be attached to a session with no installed key.
    #[error("cannot activate negotiated authority on an unkeyed Xenia session")]
    SessionHasNoKey,
    /// A cryptographically verified authority rekey may not install the all-zero key.
    #[error("verified authority rekey produced an all-zero session key")]
    ZeroRekeyKey,
}

#[cfg(feature = "handshake")]
fn require_nonzero(value: [u8; 32]) -> Result<(), NegotiatedAuthoritySessionError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(NegotiatedAuthoritySessionError::ZeroCommitment)
    } else {
        Ok(())
    }
}

#[cfg(all(test, feature = "handshake"))]
mod negotiated_session_tests {
    use super::*;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::authority_rekey_transition_evidence::{
        RekeyTransitionReasonV1, RekeyTransitionProfileV1,
    };
    use crate::negotiated_context::{CapabilityOfferEntryV1, NegotiatedCapabilityV1};

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn offers() -> (CapabilityOfferV1, CapabilityOfferV1) {
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
        (host, viewer)
    }

    fn authenticated_handshake() -> AuthenticatedNegotiatedHandshake {
        let (host, viewer) = offers();
        let negotiation = negotiate_capabilities(&host, &viewer).unwrap();
        let base_v4 = core::array::from_fn(|index| index as u8);
        let v5 = compose_v5_context(&base_v4, &negotiation.binding_hash());
        AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host,
            viewer,
            base_v4,
            v5,
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap()
    }

    fn activated_session(profile: RekeyTransitionProfileV1) -> NegotiatedAuthoritySession {
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        let activation = authenticated_handshake()
            .narrow_to_causal_authority(&policy)
            .unwrap();
        let mut session = Session::new();
        session.install_key([0x55; 32]);
        NegotiatedAuthoritySession::activate(session, activation, profile).unwrap()
    }

    #[test]
    fn authenticated_v5_is_recomputed_before_proof_exists() {
        let (host, viewer) = offers();
        assert!(matches!(
            AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
                host,
                viewer,
                [0x33; 32],
                [0x44; 32],
                [0x55; 32],
                [0x66; 32],
            ),
            Err(NegotiatedAuthoritySessionError::NegotiatedV5Mismatch)
        ));
    }

    #[test]
    fn local_policy_narrowing_is_distinct_from_authenticated_negotiation() {
        let proof = authenticated_handshake();
        assert!(proof.selected_context().contains(b"xenia.causal-authority", b"draft-04"));

        let authority = causal_authority_draft04_capability();
        let strict = NegotiationPolicyV1::allow_list([authority.clone()], [authority]).unwrap();
        assert!(proof.narrow_to_causal_authority(&strict).is_err());
    }

    #[test]
    fn authority_requires_an_already_keyed_session() {
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        let activation = authenticated_handshake()
            .narrow_to_causal_authority(&policy)
            .unwrap();
        assert!(matches!(
            NegotiatedAuthoritySession::activate(
                Session::new(),
                activation,
                RekeyTransitionProfileV1::OperatorChannelV1,
            ),
            Err(NegotiatedAuthoritySessionError::SessionHasNoKey)
        ));
    }

    #[test]
    fn verified_rekey_advances_key_and_lineage_together() {
        let mut authority = activated_session(RekeyTransitionProfileV1::OperatorChannelV1);
        let before = authority.session().session_fingerprint(7).unwrap();
        let transition = AuthorityRekeyTransitionEvidenceV1::operator(
            1,
            authority.activation_receipt().handshake_transcript_hash,
            authority.lineage().current_epoch_hash,
            RekeyTransitionReasonV1::OperatorInterval,
        )
        .unwrap();
        let verified = VerifiedAuthorityRekey::from_verified_transition(transition, [0x77; 32]).unwrap();
        authority.apply_verified_rekey(verified).unwrap();

        assert_eq!(authority.lineage().key_epoch, 1);
        let after = authority.session().session_fingerprint(7).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn rejected_profile_switch_does_not_mutate_the_session_key() {
        let mut authority = activated_session(RekeyTransitionProfileV1::OperatorChannelV1);
        let before = authority.session().session_fingerprint(9).unwrap();
        let lane = AuthorityRekeyTransitionEvidenceV1::lane(
            1,
            authority.activation_receipt().handshake_transcript_hash,
            authority.lineage().current_epoch_hash,
            RekeyTransitionReasonV1::LaneManual,
        )
        .unwrap();
        let verified = VerifiedAuthorityRekey::from_verified_transition(lane, [0x88; 32]).unwrap();
        assert!(authority.apply_verified_rekey(verified).is_err());
        assert_eq!(authority.lineage().key_epoch, 0);
        assert_eq!(before, authority.session().session_fingerprint(9).unwrap());
    }

    #[test]
    fn dropping_authority_requires_consuming_back_to_raw_session() {
        let authority = activated_session(RekeyTransitionProfileV1::LaneSessionV1);
        let mut raw = authority.into_raw_session();
        raw.install_key([0x99; 32]);
        assert!(raw.has_key());
    }

    #[test]
    fn zero_rekey_key_cannot_be_packaged_as_verified_authority_rekey() {
        let authority = activated_session(RekeyTransitionProfileV1::OperatorChannelV1);
        let transition = AuthorityRekeyTransitionEvidenceV1::operator(
            1,
            authority.activation_receipt().handshake_transcript_hash,
            authority.lineage().current_epoch_hash,
            RekeyTransitionReasonV1::OperatorManual,
        )
        .unwrap();
        assert!(matches!(
            VerifiedAuthorityRekey::from_verified_transition(transition, [0; 32]),
            Err(NegotiatedAuthoritySessionError::ZeroRekeyKey)
        ));
    }

    #[test]
    fn selected_context_profile_gate_still_applies_at_activation() {
        let selected = NegotiatedContextV1::from_capabilities([
            causal_authority_draft04_capability(),
            NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec()).unwrap(),
        ])
        .unwrap();
        assert!(selected.contains(b"xenia.operator-rekey", b"v1"));
        let authority = activated_session(RekeyTransitionProfileV1::OperatorChannelV1);
        assert_eq!(authority.selected_context().hash(), selected.hash());
    }
}
