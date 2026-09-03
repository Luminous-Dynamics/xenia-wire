// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Post-commit receiver-rekey typestate for the Ack delivery ambiguity window.
//!
//! This module is deliberately additive prototype input for ARR-011.  The
//! existing receiver transaction in [`crate::authority_session`] performs the
//! cryptographic/replay/lineage transition.  This layer changes only ownership:
//! once that transaction commits, the active authority session is moved into
//! [`AuthorityRekeyAckDeliveryPending`] and cannot be used independently until a
//! transport owner resolves the exact presealed Ack handoff.
//!
//! The compiler-visible boundary is the important property.  Once the consuming
//! transition succeeds, the original authority value has moved:
//!
//! ```compile_fail
//! use xenia_wire::authority_session::NegotiatedAuthoritySession;
//!
//! fn cannot_use_active_authority_while_ack_is_pending(
//!     mut session: NegotiatedAuthoritySession,
//!     sealed_proposal: &[u8],
//! ) {
//!     let pending = session
//!         .accept_operator_rekey_proposal_pending(sealed_proposal)
//!         .unwrap();
//!     session.tick(); // rejected: `session` moved into `pending`
//!     drop(pending);
//! }
//! ```
//!
//! The pending state intentionally has no unrestricted raw-session escape hatch:
//!
//! ```compile_fail
//! use xenia_wire::authority_rekey_pending::AuthorityRekeyAckDeliveryPending;
//!
//! fn cannot_bypass_delivery_barrier(pending: AuthorityRekeyAckDeliveryPending) {
//!     let _raw = pending.into_raw_session();
//! }
//! ```
//!
//! This still cannot prove remote receipt or make a network transport
//! transactional.  The production transport continuation must consume the whole
//! pending value by ownership, make one carrier send attempt with
//! [`AuthorityRekeyAckDeliveryPending::pending_ack`], call
//! [`AuthorityRekeyAckDeliveryPending::delivery_succeeded`] only for its defined
//! local-success outcome, and otherwise consume the state through
//! [`AuthorityRekeyAckDeliveryPending::into_ambiguous_evidence`] or teardown.

#![cfg(all(
    feature = "causal-authority",
    feature = "handshake",
    feature = "operator-rekey"
))]

use core::fmt;

use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_transition_evidence::AuthorityRekeyTransitionEvidenceV1;
use crate::authority_session::{
    AuthorityOperatorRekeyAcceptance, AuthorityOperatorRekeyError, NegotiatedAuthoritySession,
    PendingAuthorityOperatorRekeyAck,
};

/// Pre-commit receiver-rekey rejection that returns ownership of the still-live
/// authority session together with the rejection reason.
///
/// Authentication may already have consumed the offending envelope's live replay
/// slot before a semantic rejection occurs.  Returning the session is therefore
/// **not** replay rollback; it only preserves the current key/lineage authority
/// object when the receiver transaction did not cross its commit boundary.
///
/// The session is boxed so this error carrier remains compact under strict
/// Clippy `result_large_err` qualification.  Boxing changes representation only;
/// ownership still returns exclusively through [`Self::into_parts`].
#[must_use = "a rejected receiver rekey attempt still owns the live authority session"]
pub struct AuthorityRekeyRejected {
    authority: Box<NegotiatedAuthoritySession>,
    error: AuthorityOperatorRekeyError,
}

impl AuthorityRekeyRejected {
    /// Rejection reason without releasing ownership of the live authority session.
    pub fn error(&self) -> &AuthorityOperatorRekeyError {
        &self.error
    }

    /// Recover the still-live authority session and the rejection reason.
    ///
    /// Any authenticated replay state consumed before semantic rejection remains
    /// consumed inside the returned session.
    pub fn into_parts(self) -> (NegotiatedAuthoritySession, AuthorityOperatorRekeyError) {
        (*self.authority, self.error)
    }
}

impl fmt::Debug for AuthorityRekeyRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyRejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Authority session after the receiver rekey transaction has committed but
/// before the exact presealed Ack delivery outcome is known.
///
/// The active [`NegotiatedAuthoritySession`] is private and owned by this value.
/// Safe callers cannot independently verify/use authority, mutate the session, or
/// escape to a raw session while the Ack ambiguity window is open.
#[must_use = "committed receiver rekey must resolve Ack delivery or terminate the connection generation"]
pub struct AuthorityRekeyAckDeliveryPending {
    authority: NegotiatedAuthoritySession,
    acceptance: AuthorityOperatorRekeyAcceptance,
}

impl AuthorityRekeyAckDeliveryPending {
    /// Exact single-owner, presealed sequence-zero Ack delivery capability.
    ///
    /// The final transport owner should borrow these bytes only inside its one
    /// carrier send attempt.  The whole pending typestate remains owned by that
    /// transport continuation until the outcome is resolved.
    pub fn pending_ack(&self) -> &PendingAuthorityOperatorRekeyAck {
        self.acceptance.pending_ack()
    }

    /// Durable public evidence for the committed authority rekey transition.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        self.acceptance.transition()
    }

    /// Durable authority-lineage position after the committed transition.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        self.acceptance.lineage()
    }

    /// Resolve the local Ack-delivery barrier after the transport owner reports
    /// its defined successful handoff outcome.
    ///
    /// This is the only API on the pending typestate that returns the active
    /// new-epoch authority session.  The pending Ack token is consumed/dropped;
    /// durable transition and lineage evidence are returned alongside authority.
    /// This method does not itself prove that a carrier send occurred.
    pub fn delivery_succeeded(
        self,
    ) -> (
        NegotiatedAuthoritySession,
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        let Self {
            authority,
            acceptance,
        } = self;
        let (_pending_ack, transition, lineage) = acceptance.into_parts();
        (authority, transition, lineage)
    }

    /// Terminate the local authority generation after failed/ambiguous Ack
    /// delivery while retaining only durable audit evidence.
    ///
    /// The owned active authority session and pending Ack capability are consumed
    /// and dropped.  No API returns either one from this ambiguity path, so
    /// recovery requires a fresh authenticated session/authority activation.
    pub fn into_ambiguous_evidence(
        self,
    ) -> (
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        let Self {
            authority,
            acceptance,
        } = self;
        drop(authority);
        let (_pending_ack, transition, lineage) = acceptance.into_parts();
        (transition, lineage)
    }
}

impl fmt::Debug for AuthorityRekeyAckDeliveryPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyAckDeliveryPending")
            .field("transition", self.transition())
            .field("lineage", self.lineage())
            .finish_non_exhaustive()
    }
}

impl NegotiatedAuthoritySession {
    /// Consume this active authority session through one receiver-side operator
    /// rekey attempt and expose an explicit post-commit Ack-delivery typestate.
    ///
    /// - Rejection before the existing receiver commit boundary returns
    ///   [`AuthorityRekeyRejected`], which owns the still-live session plus the
    ///   rejection reason.  Authenticated semantic rejection remains
    ///   replay-consumed exactly as in the underlying receiver transaction.
    /// - Success returns [`AuthorityRekeyAckDeliveryPending`].  The committed
    ///   authority session is no longer independently available until the
    ///   transport owner resolves Ack delivery.
    ///
    /// This additive prototype intentionally delegates cryptographic behavior to
    /// [`NegotiatedAuthoritySession::accept_operator_rekey_proposal`].  The final
    /// reconstructed receiver should make this ownership shape the primary API
    /// after strict expected-domain/current-key receive is integrated.
    pub fn accept_operator_rekey_proposal_pending(
        self,
        sealed_proposal: &[u8],
    ) -> Result<AuthorityRekeyAckDeliveryPending, AuthorityRekeyRejected> {
        let mut authority = self;
        match authority.accept_operator_rekey_proposal(sealed_proposal) {
            Ok(acceptance) => Ok(AuthorityRekeyAckDeliveryPending {
                authority,
                acceptance,
            }),
            Err(error) => Err(AuthorityRekeyRejected {
                authority: Box::new(authority),
                error,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Session;
    use crate::WireError;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::authority_session::AuthenticatedNegotiatedHandshake;
    use crate::handshake::SessionKeySchedule;
    use crate::handshake_v2_contract::compose_v5_context;
    use crate::negotiated_context::{
        CapabilityOfferEntryV1, CapabilityOfferV1, negotiate_capabilities,
    };
    use crate::negotiation_policy::NegotiationPolicyV1;
    use crate::operator_rekey::{
        OperatorRekeyMessage, OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY,
    };

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

    fn authority() -> NegotiatedAuthoritySession {
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
        let proof = AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host, viewer, base_v4, v5, schedule,
        )
        .unwrap();
        let installed = proof
            .install_into(Session::with_source_id(SOURCE_ID, SESSION_EPOCH))
            .unwrap();
        let policy =
            NegotiationPolicyV1::minimum_required([causal_authority_draft04_capability()]).unwrap();
        installed.narrow_to_causal_authority(&policy).unwrap()
    }

    fn seal_operator_message(key: [u8; 32], message: &OperatorRekeyMessage) -> Vec<u8> {
        let mut sender = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
        sender.install_key(key);
        sender
            .seal(&message.encode().unwrap(), PAYLOAD_TYPE_OPERATOR_REKEY)
            .unwrap()
    }

    fn valid_epoch_one_proposal() -> OperatorRekeyMessage {
        crate::operator_rekey::propose(
            1,
            [0x11; 32],
            [0x11; 32],
            OperatorRekeyReason::Manual,
        )
        .unwrap()
    }

    #[test]
    fn semantic_rejection_returns_session_without_replay_rollback() {
        let authority = authority();
        let unexpected_ack = OperatorRekeyMessage::Ack {
            key_epoch: 1,
            epoch_hash: [0x77; 32],
        };
        let sealed = seal_operator_message(AEAD, &unexpected_ack);

        let rejected = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap_err();
        assert!(matches!(
            rejected.error(),
            &AuthorityOperatorRekeyError::UnexpectedAck
        ));
        let (mut authority, error) = rejected.into_parts();
        assert!(matches!(error, AuthorityOperatorRekeyError::UnexpectedAck));

        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed),
            Err(AuthorityOperatorRekeyError::Wire(WireError::OpenFailed))
        ));
    }

    #[test]
    fn success_withholds_then_reactivates_new_epoch_authority() {
        let authority = authority();
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);

        let pending = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap();
        assert_eq!(pending.transition().key_epoch, 1);
        assert_eq!(pending.lineage().key_epoch, 1);
        assert_eq!(&pending.pending_ack().as_bytes()[8..12], &[0, 0, 0, 0]);

        let (authority, transition, lineage) = pending.delivery_succeeded();
        assert_eq!(transition.key_epoch, 1);
        assert_eq!(lineage.key_epoch, 1);
        assert_eq!(authority.lineage(), &lineage);
        assert_eq!(authority.session().nonce_counter(), 1);
    }

    #[test]
    fn ambiguity_resolution_returns_only_durable_evidence() {
        let authority = authority();
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap();

        let (transition, lineage) = pending.into_ambiguous_evidence();
        assert_eq!(transition.key_epoch, 1);
        assert_eq!(lineage.key_epoch, 1);
    }
}
