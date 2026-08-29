// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Public safety facade for exact authority bound to a live Xenia Wire session.
//!
//! The generic implementation staged in `authority_session_core` remains private
//! so this public API can enforce a transport-specific invariant: [`crate::Session`]
//! owns one AEAD key, therefore its authority-preserving rekey path is the
//! operator-channel domain only. The distinct `LaneSessionV1` domain belongs to
//! xenia-peer's native multi-lane session layer and is not exposed here.

#[path = "authority_session_core.rs"]
mod core;

pub use core::{
    AuthenticatedAuthorityActivation, AuthenticatedNegotiatedHandshake, AuthoritySessionError,
    NegotiatedAuthoritySessionError, VerifiedAuthorityRekey,
    sign_causal_authority_response_for_session,
    verify_approved_external_action_authority_for_session,
};

use crate::Session;
use crate::authority::{CausalAuthorityResponse, VerifiedExternalActionAuthority};
use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_profile_binding::AuthorityRekeyProfileBindingV1;
use crate::authority_rekey_transition_evidence::RekeyTransitionProfileV1;
use crate::consent::{ConsentRequest, ConsentRevocation, PUBLIC_KEY_LEN};
use crate::negotiated_context::NegotiatedContextV1;

/// Authority-capable single-key envelope session.
///
/// This facade owns the private generic authority-session state but fixes its
/// rekey profile to [`RekeyTransitionProfileV1::OperatorChannelV1`]. There is no
/// public constructor accepting an arbitrary profile, so safe downstream code
/// cannot attach multi-lane rekey semantics to a one-key [`Session`].
pub struct NegotiatedAuthoritySession {
    inner: core::NegotiatedAuthoritySession,
}

impl NegotiatedAuthoritySession {
    /// Activate negotiated authority on a single-key Xenia Wire session.
    ///
    /// The activation still proves that the raw session's current AEAD key
    /// matches the authenticated V2 key schedule. In addition, this facade
    /// always pins operator-channel rekey semantics; exact negotiated
    /// `xenia.operator-rekey / v1` support is therefore required by the existing
    /// profile-binding gate.
    pub fn activate(
        session: Session,
        activation: AuthenticatedAuthorityActivation,
    ) -> Result<Self, NegotiatedAuthoritySessionError> {
        let inner = core::NegotiatedAuthoritySession::activate(
            session,
            activation,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )?;
        Ok(Self { inner })
    }

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
    /// online-use API. External callers should prefer
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

    /// Apply a replacement key only after the private authority state validates
    /// verified operator-rekey evidence, capability binding, and epoch continuity.
    pub fn apply_verified_rekey(
        &mut self,
        verified: VerifiedAuthorityRekey,
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
    use crate::handshake::SessionKeySchedule;
    use crate::handshake_v2_contract::compose_v5_context;
    use crate::negotiated_context::{
        CapabilityOfferEntryV1, CapabilityOfferV1, negotiate_capabilities,
    };
    use crate::negotiation_policy::NegotiationPolicyV1;

    const AEAD: [u8; 32] = [0x55; 32];

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn activation() -> AuthenticatedAuthorityActivation {
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
        let base_v4 = core::array::from_fn(|index| index as u8);
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
        let proof = AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host, viewer, base_v4, v5, schedule,
        )
        .unwrap();
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        proof.narrow_to_causal_authority(&policy).unwrap()
    }

    #[test]
    fn public_wire_session_is_always_operator_rekey_bound() {
        let mut raw = Session::new();
        raw.install_key(AEAD);
        let authority = NegotiatedAuthoritySession::activate(raw, activation()).unwrap();
        assert_eq!(
            authority.rekey_profile_binding().profile,
            RekeyTransitionProfileV1::OperatorChannelV1
        );
    }
}
