// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Failure-atomic receiver-side operator rekey for negotiated authority.
//!
//! This module is crate-private on purpose. External callers never hand an
//! already-decoded [`OperatorRekeyMessage`] or a replacement AEAD key to an
//! authority session. The receiver starts from a sealed `0x31` envelope and the
//! live session authenticates it itself.
//!
//! The transition is prepared before any live key/authority mutation:
//!
//! 1. route only `PAYLOAD_TYPE_OPERATOR_REKEY`;
//! 2. AEAD-open through the live session (which legitimately commits replay
//!    acceptance for an authenticated envelope);
//! 3. require a Proposal and independently recompute its epoch hash;
//! 4. construct public operator-transition evidence and precompute the next
//!    profile-bound authority lineage;
//! 5. derive the replacement key from the private authenticated rekey root;
//! 6. encode and encrypt the Ack under the replacement key at sequence zero in
//!    a temporary nonce-domain-identical session;
//! 7. only after every fallible step succeeds, install the replacement key in
//!    the live session, reserve sequence zero, and assign the precomputed
//!    lineage.
//!
//! The prepared token never escapes this module, so there is no public or
//! crate-wide `commit(new_key, transition)` seam to mispair.

#![cfg(all(
    feature = "causal-authority",
    feature = "handshake",
    feature = "operator-rekey"
))]

use zeroize::Zeroizing;

use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_profile_binding::{
    AuthorityRekeyProfileBindingError, AuthorityRekeyProfileBindingV1,
    advance_profile_bound_lineage_after_verified_transition,
};
use crate::authority_rekey_transition_evidence::{
    AuthorityRekeyTransitionEvidenceError, AuthorityRekeyTransitionEvidenceV1,
    RekeyTransitionReasonV1,
};
use crate::negotiated_context::NegotiatedContextV1;
use crate::operator_rekey::{
    OperatorRekeyMessage, OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY,
    derive_operator_rekey_key, verify_proposal_epoch_hash,
};
use crate::{Session, WireError, envelope_payload_type};

/// Receiver-side result after a fully committed authority-preserving operator
/// rekey.
///
/// Kept crate-private until the public [`crate::authority_session`] facade wires
/// the operation into its owned session. The sealed Ack is ready for the
/// transport owner to send; it is the replacement key epoch's sequence-zero
/// envelope.
pub(crate) struct ReceivedOperatorRekeyAcceptance {
    pub(crate) sealed_ack: Vec<u8>,
    pub(crate) transition: AuthorityRekeyTransitionEvidenceV1,
    pub(crate) lineage: AuthorityLineageEpochEvidenceV1,
}

/// Private, non-cloneable prepared transaction. All fields are intentionally
/// inaccessible outside this module so a derived key cannot be separated from
/// the exact transition/lineage/Ack it was prepared for.
struct PreparedReceivedOperatorRekey {
    new_key: Zeroizing<[u8; 32]>,
    transition: AuthorityRekeyTransitionEvidenceV1,
    next_lineage: AuthorityLineageEpochEvidenceV1,
    sealed_ack: Vec<u8>,
}

/// Authenticate, validate, prepare and commit one received operator-rekey
/// Proposal as a single receiver-side authority operation.
///
/// On error, the current live AEAD key, outbound nonce counter and authority
/// lineage are unchanged. An authenticated envelope may nevertheless consume a
/// replay-window sequence before a later semantic check rejects its plaintext;
/// that is intentional anti-replay behavior, not authority-state mutation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_and_commit_operator_rekey(
    session: &mut Session,
    lineage: &mut AuthorityLineageEpochEvidenceV1,
    activation: &AuthorityActivationReceiptV1,
    selected_context: &NegotiatedContextV1,
    profile_binding: &AuthorityRekeyProfileBindingV1,
    rekey_root: &[u8; 32],
    envelope: &[u8],
) -> Result<ReceivedOperatorRekeyAcceptance, OperatorAuthorityRekeyError> {
    let prepared = prepare_received_operator_rekey(
        session,
        lineage,
        activation,
        selected_context,
        profile_binding,
        rekey_root,
        envelope,
    )?;
    Ok(commit_received_operator_rekey(session, lineage, prepared))
}

#[allow(clippy::too_many_arguments)]
fn prepare_received_operator_rekey(
    session: &mut Session,
    lineage: &AuthorityLineageEpochEvidenceV1,
    activation: &AuthorityActivationReceiptV1,
    selected_context: &NegotiatedContextV1,
    profile_binding: &AuthorityRekeyProfileBindingV1,
    rekey_root: &[u8; 32],
    envelope: &[u8],
) -> Result<PreparedReceivedOperatorRekey, OperatorAuthorityRekeyError> {
    if envelope_payload_type(envelope) != Some(PAYLOAD_TYPE_OPERATOR_REKEY) {
        return Err(OperatorAuthorityRekeyError::UnexpectedPayloadType);
    }

    // `Session::open` performs AEAD authentication before replay acceptance.
    // Once this succeeds, replay state is allowed to advance even if a later
    // semantic rekey check rejects the authenticated plaintext.
    let plaintext = session.open(envelope)?;
    let message = OperatorRekeyMessage::decode(&plaintext)?;

    let OperatorRekeyMessage::Proposal {
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash: claimed_epoch_hash,
    } = message
    else {
        return Err(OperatorAuthorityRekeyError::ExpectedProposal);
    };

    let verified_epoch_hash = verify_proposal_epoch_hash(
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        claimed_epoch_hash,
    )?;

    let evidence_reason = match reason {
        OperatorRekeyReason::Interval => RekeyTransitionReasonV1::OperatorInterval,
        OperatorRekeyReason::Manual => RekeyTransitionReasonV1::OperatorManual,
    };
    let transition = AuthorityRekeyTransitionEvidenceV1::operator(
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        evidence_reason,
    )?;

    // The protocol verifier and the durable-evidence mirror independently
    // reproduce the historical operator epoch hash. Refuse authority continuity
    // if those two implementations ever diverge.
    if transition.epoch_hash != verified_epoch_hash {
        return Err(OperatorAuthorityRekeyError::TransitionHashDivergence);
    }

    // This enforces exact next epoch, parent hash, activation transcript root,
    // negotiated operator-rekey capability and the immutable profile binding.
    let next_lineage = advance_profile_bound_lineage_after_verified_transition(
        lineage,
        activation,
        selected_context,
        profile_binding,
        &transition,
    )?;

    let new_key = Zeroizing::new(derive_operator_rekey_key(rekey_root, &verified_epoch_hash));
    if new_key.iter().all(|byte| *byte == 0) {
        return Err(OperatorAuthorityRekeyError::ZeroDerivedKey);
    }

    let ack = OperatorRekeyMessage::Ack {
        key_epoch,
        epoch_hash: verified_epoch_hash,
    };
    let ack_plaintext = ack.encode()?;

    // Prepare the exact sequence-zero Ack without touching the live session.
    // The temporary session has the same local nonce domain, but its only use is
    // this one encryption. It is dropped before the live key is committed.
    let mut ack_session = Session::with_source_id(*session.source_id(), session.epoch());
    ack_session.install_key(*new_key);
    let sealed_ack = ack_session.seal(&ack_plaintext, PAYLOAD_TYPE_OPERATOR_REKEY)?;
    debug_assert_eq!(ack_session.nonce_counter(), 1);

    Ok(PreparedReceivedOperatorRekey {
        new_key,
        transition,
        next_lineage,
        sealed_ack,
    })
}

/// Commit a transaction whose every fallible cryptographic/evidence operation
/// has already succeeded. This function is deliberately infallible.
fn commit_received_operator_rekey(
    session: &mut Session,
    lineage: &mut AuthorityLineageEpochEvidenceV1,
    prepared: PreparedReceivedOperatorRekey,
) -> ReceivedOperatorRekeyAcceptance {
    session.install_key(*prepared.new_key);

    // Sequence zero was already used by `prepared.sealed_ack`. Reserve it in
    // the live sender state so the next normal envelope is sequence one rather
    // than catastrophic nonce reuse under the new key.
    let reserved = session.next_nonce();
    debug_assert_eq!(reserved, 0);
    debug_assert_eq!(session.nonce_counter(), 1);

    *lineage = prepared.next_lineage;
    ReceivedOperatorRekeyAcceptance {
        sealed_ack: prepared.sealed_ack,
        transition: prepared.transition,
        lineage: prepared.next_lineage,
    }
}

/// Receiver-side authority-preserving operator-rekey failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OperatorAuthorityRekeyError {
    /// Handler was given an envelope outside the negotiated operator-rekey
    /// payload domain. This is checked before AEAD open/replay acceptance.
    #[error("authority operator-rekey handler requires payload type 0x31")]
    UnexpectedPayloadType,
    /// Envelope was authentic but carried an Ack where the receiver requires a
    /// Proposal.
    #[error("authority operator-rekey receiver expected a Proposal, not an Ack")]
    ExpectedProposal,
    /// The operator protocol verifier and durable transition-evidence mirror
    /// disagreed about the canonical epoch hash.
    #[error("operator rekey verifier and authority transition evidence disagree on epoch hash")]
    TransitionHashDivergence,
    /// HKDF produced the forbidden all-zero replacement-key sentinel.
    #[error("operator rekey derived an all-zero replacement key")]
    ZeroDerivedKey,
    /// Envelope AEAD/codec or operator proposal self-consistency failed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Durable public transition evidence was malformed.
    #[error(transparent)]
    Transition(#[from] AuthorityRekeyTransitionEvidenceError),
    /// Profile/capability/activation/lineage continuity rejected the transition.
    #[error(transparent)]
    Profile(#[from] AuthorityRekeyProfileBindingError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
    use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::authority_rekey_profile_binding::AuthorityRekeyProfileBindingV1;
    use crate::authority_rekey_transition_evidence::RekeyTransitionProfileV1;
    use crate::negotiated_context::{NegotiatedCapabilityV1, NegotiatedContextV1};
    use crate::operator_rekey::{OperatorRekeyMessage, OperatorRekeyReason, propose};

    const OLD_KEY: [u8; 32] = [0x41; 32];
    const REKEY_ROOT: [u8; 32] = [0x52; 32];

    fn selected_context() -> NegotiatedContextV1 {
        NegotiatedContextV1::from_capabilities([
            causal_authority_draft04_capability(),
            NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec())
                .unwrap(),
        ])
        .unwrap()
    }

    fn activation(selected: &NegotiatedContextV1) -> AuthorityActivationReceiptV1 {
        AuthorityActivationReceiptV1 {
            schema_version: 1,
            handshake_transcript_hash: [0x11; 32],
            base_v4_context_hash: [0x22; 32],
            final_v5_context_hash: [0x33; 32],
            host_offer_hash: [0x44; 32],
            viewer_offer_hash: [0x55; 32],
            selected_context_hash: selected.hash(),
            negotiation_binding_hash: [0x66; 32],
            local_policy_hash: [0x77; 32],
            host_identity_fingerprint: [0x88; 32],
            lineage_id: [0x99; 32],
            activation_id: [0xaa; 32],
        }
    }

    fn context() -> (
        NegotiatedContextV1,
        AuthorityActivationReceiptV1,
        AuthorityRekeyProfileBindingV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        let selected = selected_context();
        let activation = activation(&selected);
        let binding = AuthorityRekeyProfileBindingV1::new(
            &activation,
            &selected,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )
        .unwrap();
        let lineage = AuthorityLineageEpochEvidenceV1::initial(&activation).unwrap();
        (selected, activation, binding, lineage)
    }

    fn seal_message(message: &OperatorRekeyMessage, payload_type: u8) -> Vec<u8> {
        let mut sender = Session::with_source_id([0x21; 8], 7);
        sender.install_key(OLD_KEY);
        sender.seal(&message.encode().unwrap(), payload_type).unwrap()
    }

    #[test]
    fn valid_proposal_commits_key_lineage_and_sequence_zero_ack_together() {
        let (selected, activation, binding, mut lineage) = context();
        let proposal = propose(
            1,
            activation.handshake_transcript_hash,
            lineage.current_epoch_hash,
            OperatorRekeyReason::Interval,
        )
        .unwrap();
        let envelope = seal_message(&proposal, PAYLOAD_TYPE_OPERATOR_REKEY);

        let mut receiver = Session::with_source_id([0x31; 8], 9);
        receiver.install_key(OLD_KEY);
        let before = receiver.session_fingerprint(7).unwrap();

        let accepted = receive_and_commit_operator_rekey(
            &mut receiver,
            &mut lineage,
            &activation,
            &selected,
            &binding,
            &REKEY_ROOT,
            &envelope,
        )
        .unwrap();

        assert_eq!(lineage.key_epoch, 1);
        assert_eq!(accepted.lineage, lineage);
        assert_eq!(accepted.transition.key_epoch, 1);
        assert_eq!(receiver.nonce_counter(), 1);
        assert_ne!(before, receiver.session_fingerprint(7).unwrap());

        let next_key = derive_operator_rekey_key(&REKEY_ROOT, &lineage.current_epoch_hash);
        let mut ack_receiver = Session::new();
        ack_receiver.install_key(next_key);
        let ack_plaintext = ack_receiver.open(&accepted.sealed_ack).unwrap();
        assert_eq!(
            OperatorRekeyMessage::decode(&ack_plaintext).unwrap(),
            OperatorRekeyMessage::Ack {
                key_epoch: 1,
                epoch_hash: lineage.current_epoch_hash,
            }
        );

        // The prepared Ack consumed new-key sequence zero. The first subsequent
        // live envelope must therefore use sequence one.
        let subsequent = receiver
            .seal(b"after-rekey", PAYLOAD_TYPE_OPERATOR_REKEY)
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(subsequent[8..12].try_into().unwrap()),
            1
        );
    }

    #[test]
    fn wrong_payload_type_is_rejected_before_replay_acceptance() {
        let (selected, activation, binding, mut lineage) = context();
        let proposal = propose(
            1,
            activation.handshake_transcript_hash,
            lineage.current_epoch_hash,
            OperatorRekeyReason::Manual,
        )
        .unwrap();
        let envelope = seal_message(&proposal, 0x32);
        let mut receiver = Session::new();
        receiver.install_key(OLD_KEY);

        assert!(matches!(
            receive_and_commit_operator_rekey(
                &mut receiver,
                &mut lineage,
                &activation,
                &selected,
                &binding,
                &REKEY_ROOT,
                &envelope,
            ),
            Err(OperatorAuthorityRekeyError::UnexpectedPayloadType)
        ));

        // Handler never called `open`, so the same authentic envelope remains
        // available to the correct payload-domain handler.
        assert!(receiver.open(&envelope).is_ok());
        assert_eq!(lineage.key_epoch, 0);
    }

    #[test]
    fn authenticated_bad_proposal_consumes_replay_but_not_authority_state() {
        let (selected, activation, binding, mut lineage) = context();
        let proposal = propose(
            1,
            activation.handshake_transcript_hash,
            lineage.current_epoch_hash,
            OperatorRekeyReason::Manual,
        )
        .unwrap();
        let OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            ..
        } = proposal
        else {
            unreachable!()
        };
        let bad = OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash: [0xff; 32],
        };
        let envelope = seal_message(&bad, PAYLOAD_TYPE_OPERATOR_REKEY);

        let mut receiver = Session::new();
        receiver.install_key(OLD_KEY);
        let fingerprint = receiver.session_fingerprint(11).unwrap();
        let nonce_counter = receiver.nonce_counter();
        let lineage_before = lineage;

        assert!(receive_and_commit_operator_rekey(
            &mut receiver,
            &mut lineage,
            &activation,
            &selected,
            &binding,
            &REKEY_ROOT,
            &envelope,
        )
        .is_err());

        assert_eq!(receiver.session_fingerprint(11).unwrap(), fingerprint);
        assert_eq!(receiver.nonce_counter(), nonce_counter);
        assert_eq!(lineage, lineage_before);
        // AEAD authentication succeeded before semantic rejection, so replaying
        // the exact same envelope is correctly refused.
        assert!(receiver.open(&envelope).is_err());
    }

    #[test]
    fn ack_cannot_be_used_as_a_received_rekey_proposal() {
        let (selected, activation, binding, mut lineage) = context();
        let ack = OperatorRekeyMessage::Ack {
            key_epoch: 1,
            epoch_hash: [0x33; 32],
        };
        let envelope = seal_message(&ack, PAYLOAD_TYPE_OPERATOR_REKEY);
        let mut receiver = Session::new();
        receiver.install_key(OLD_KEY);
        let before = receiver.session_fingerprint(13).unwrap();

        assert!(matches!(
            receive_and_commit_operator_rekey(
                &mut receiver,
                &mut lineage,
                &activation,
                &selected,
                &binding,
                &REKEY_ROOT,
                &envelope,
            ),
            Err(OperatorAuthorityRekeyError::ExpectedProposal)
        ));
        assert_eq!(lineage.key_epoch, 0);
        assert_eq!(receiver.session_fingerprint(13).unwrap(), before);
    }

    #[test]
    fn skipped_epoch_and_wrong_parent_fail_before_key_commit() {
        let (selected, activation, binding, mut lineage) = context();
        let proposal = propose(
            2,
            activation.handshake_transcript_hash,
            [0xee; 32],
            OperatorRekeyReason::Interval,
        )
        .unwrap();
        let envelope = seal_message(&proposal, PAYLOAD_TYPE_OPERATOR_REKEY);
        let mut receiver = Session::new();
        receiver.install_key(OLD_KEY);
        let before = receiver.session_fingerprint(17).unwrap();

        assert!(receive_and_commit_operator_rekey(
            &mut receiver,
            &mut lineage,
            &activation,
            &selected,
            &binding,
            &REKEY_ROOT,
            &envelope,
        )
        .is_err());
        assert_eq!(lineage.key_epoch, 0);
        assert_eq!(receiver.session_fingerprint(17).unwrap(), before);
        assert_eq!(receiver.nonce_counter(), 0);
    }
}