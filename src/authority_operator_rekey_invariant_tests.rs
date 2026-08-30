// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use zeroize::Zeroizing;

use crate::Session;
use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_negotiation::causal_authority_draft04_capability;
use crate::authority_operator_rekey::{
    OperatorAuthorityRekeyError, receive_and_commit_operator_rekey,
};
use crate::authority_rekey_profile_binding::AuthorityRekeyProfileBindingV1;
use crate::authority_rekey_transition_evidence::RekeyTransitionProfileV1;
use crate::negotiated_context::{NegotiatedCapabilityV1, NegotiatedContextV1};
use crate::operator_rekey::{
    OperatorRekeyMessage, OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY,
    derive_operator_rekey_key, propose,
};

const LIVE_KEY: [u8; 32] = [0x41; 32];
const WRONG_CACHED_KEY: [u8; 32] = [0x42; 32];
const REKEY_ROOT: [u8; 32] = [0x52; 32];

fn selected_context() -> NegotiatedContextV1 {
    NegotiatedContextV1::from_capabilities([
        causal_authority_draft04_capability(),
        NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec()).unwrap(),
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

fn seal_proposal(proposal: &OperatorRekeyMessage, key: [u8; 32]) -> Vec<u8> {
    let mut sender = Session::with_source_id([0x21; 8], 7);
    sender.install_key(key);
    sender
        .seal(&proposal.encode().unwrap(), PAYLOAD_TYPE_OPERATOR_REKEY)
        .unwrap()
}

#[test]
fn cached_current_key_drift_fails_before_live_replay_or_authority_mutation() {
    let (selected, activation, binding, mut lineage) = context();
    let proposal = propose(
        1,
        activation.handshake_transcript_hash,
        lineage.current_epoch_hash,
        OperatorRekeyReason::Manual,
    )
    .unwrap();
    let envelope = seal_proposal(&proposal, LIVE_KEY);

    let mut receiver = Session::with_source_id([0x31; 8], 9);
    receiver.install_key(LIVE_KEY);
    let mut cached_key = Zeroizing::new(WRONG_CACHED_KEY);
    let before_fingerprint = receiver.session_fingerprint(29).unwrap();
    let before_nonce = receiver.nonce_counter();
    let before_lineage = lineage;

    assert!(matches!(
        receive_and_commit_operator_rekey(
            &mut receiver,
            &mut cached_key,
            &mut lineage,
            &activation,
            &selected,
            &binding,
            &REKEY_ROOT,
            &envelope,
        ),
        Err(OperatorAuthorityRekeyError::CurrentKeyInvariantMismatch)
    ));

    assert_eq!(receiver.session_fingerprint(29).unwrap(), before_fingerprint);
    assert_eq!(receiver.nonce_counter(), before_nonce);
    assert_eq!(lineage, before_lineage);
    assert_eq!(*cached_key, WRONG_CACHED_KEY);

    // The invariant check happens before the live Session::open, so the real
    // replay window has not consumed this otherwise-valid current-key envelope.
    assert!(receiver.open(&envelope).is_ok());
}

#[test]
fn zero_rekey_root_fails_before_live_replay_or_authority_mutation() {
    let (selected, activation, binding, mut lineage) = context();
    let proposal = propose(
        1,
        activation.handshake_transcript_hash,
        lineage.current_epoch_hash,
        OperatorRekeyReason::Interval,
    )
    .unwrap();
    let envelope = seal_proposal(&proposal, LIVE_KEY);

    let mut receiver = Session::new();
    receiver.install_key(LIVE_KEY);
    let mut cached_key = Zeroizing::new(LIVE_KEY);
    let before_fingerprint = receiver.session_fingerprint(31).unwrap();
    let before_lineage = lineage;

    assert!(matches!(
        receive_and_commit_operator_rekey(
            &mut receiver,
            &mut cached_key,
            &mut lineage,
            &activation,
            &selected,
            &binding,
            &[0; 32],
            &envelope,
        ),
        Err(OperatorAuthorityRekeyError::ZeroRekeyRootInvariant)
    ));

    assert_eq!(receiver.session_fingerprint(31).unwrap(), before_fingerprint);
    assert_eq!(receiver.nonce_counter(), 0);
    assert_eq!(lineage, before_lineage);
    assert_eq!(*cached_key, LIVE_KEY);
    assert!(receiver.open(&envelope).is_ok());
}

#[test]
fn kdf_must_change_key_before_lineage_can_commit() {
    let (selected, activation, binding, mut lineage) = context();
    let proposal = propose(
        1,
        activation.handshake_transcript_hash,
        lineage.current_epoch_hash,
        OperatorRekeyReason::Manual,
    )
    .unwrap();
    let epoch_hash = match &proposal {
        OperatorRekeyMessage::Proposal { epoch_hash, .. } => *epoch_hash,
        OperatorRekeyMessage::Ack { .. } => unreachable!(),
    };
    let non_rotating_current_key = derive_operator_rekey_key(&REKEY_ROOT, &epoch_hash);
    let envelope = seal_proposal(&proposal, non_rotating_current_key);

    let mut receiver = Session::new();
    receiver.install_key(non_rotating_current_key);
    let mut cached_key = Zeroizing::new(non_rotating_current_key);
    let before_fingerprint = receiver.session_fingerprint(37).unwrap();
    let before_lineage = lineage;

    assert!(matches!(
        receive_and_commit_operator_rekey(
            &mut receiver,
            &mut cached_key,
            &mut lineage,
            &activation,
            &selected,
            &binding,
            &REKEY_ROOT,
            &envelope,
        ),
        Err(OperatorAuthorityRekeyError::DerivedKeyDidNotRotate)
    ));

    assert_eq!(receiver.session_fingerprint(37).unwrap(), before_fingerprint);
    assert_eq!(receiver.nonce_counter(), 0);
    assert_eq!(lineage, before_lineage);
    assert_eq!(*cached_key, non_rotating_current_key);

    // Unlike the local invariant failures above, this anomaly is discovered only
    // after a valid current-key Proposal has passed the live replay window. The
    // exact same envelope therefore remains rejected as a replay.
    assert!(receiver.open(&envelope).is_err());
}
