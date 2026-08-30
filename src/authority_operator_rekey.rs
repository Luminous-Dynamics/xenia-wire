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
/// Kept crate-private because the public [`crate::authority_session`] facade
/// wraps it in its own receipt type. The sealed Ack is the replacement key
/// epoch's sequence-zero envelope.
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
pub enum OperatorAuthorityRekeyError {
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
#[path = "authority_operator_rekey_tests.rs"]
mod tests;
