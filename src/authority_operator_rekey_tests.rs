// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

fn seal_message_with_key(
    message: &OperatorRekeyMessage,
    payload_type: u8,
    key: [u8; 32],
    source_id: [u8; 8],
) -> Vec<u8> {
    let mut sender = Session::with_source_id(source_id, 7);
    sender.install_key(key);
    sender.seal(&message.encode().unwrap(), payload_type).unwrap()
}

fn seal_message(message: &OperatorRekeyMessage, payload_type: u8) -> Vec<u8> {
    seal_message_with_key(message, payload_type, OLD_KEY, [0x21; 8])
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
    let mut current_key = Zeroizing::new(OLD_KEY);
    let before = receiver.session_fingerprint(7).unwrap();

    let accepted = receive_and_commit_operator_rekey(
        &mut receiver,
        &mut current_key,
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
    assert_eq!(*current_key, next_key);
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
    assert_eq!(u32::from_le_bytes(subsequent[8..12].try_into().unwrap()), 1);
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
    let mut current_key = Zeroizing::new(OLD_KEY);

    assert!(matches!(
        receive_and_commit_operator_rekey(
            &mut receiver,
            &mut current_key,
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
    assert_eq!(*current_key, OLD_KEY);
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
    let mut current_key = Zeroizing::new(OLD_KEY);
    let fingerprint = receiver.session_fingerprint(11).unwrap();
    let nonce_counter = receiver.nonce_counter();
    let lineage_before = lineage;

    assert!(receive_and_commit_operator_rekey(
        &mut receiver,
        &mut current_key,
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
    assert_eq!(*current_key, OLD_KEY);
    // Exact-current AEAD authentication succeeded before semantic rejection,
    // so replaying the same envelope is correctly refused by the live window.
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
    let mut current_key = Zeroizing::new(OLD_KEY);
    let before = receiver.session_fingerprint(13).unwrap();

    assert!(matches!(
        receive_and_commit_operator_rekey(
            &mut receiver,
            &mut current_key,
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
    assert_eq!(*current_key, OLD_KEY);
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
    let mut current_key = Zeroizing::new(OLD_KEY);
    let before = receiver.session_fingerprint(17).unwrap();

    assert!(receive_and_commit_operator_rekey(
        &mut receiver,
        &mut current_key,
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
    assert_eq!(*current_key, OLD_KEY);
}

#[test]
fn previous_grace_key_cannot_drive_a_new_authority_epoch() {
    let (selected, activation, binding, mut lineage) = context();
    let mut receiver = Session::with_source_id([0x31; 8], 9);
    receiver.install_key(OLD_KEY);
    let mut current_key = Zeroizing::new(OLD_KEY);

    let epoch1 = propose(
        1,
        activation.handshake_transcript_hash,
        lineage.current_epoch_hash,
        OperatorRekeyReason::Interval,
    )
    .unwrap();
    let epoch1_envelope = seal_message_with_key(
        &epoch1,
        PAYLOAD_TYPE_OPERATOR_REKEY,
        OLD_KEY,
        [0x21; 8],
    );
    receive_and_commit_operator_rekey(
        &mut receiver,
        &mut current_key,
        &mut lineage,
        &activation,
        &selected,
        &binding,
        &REKEY_ROOT,
        &epoch1_envelope,
    )
    .unwrap();

    let epoch1_key = *current_key;
    let epoch1_lineage = lineage;
    let epoch1_fingerprint = receiver.session_fingerprint(23).unwrap();
    let epoch1_nonce = receiver.nonce_counter();

    let epoch2 = propose(
        2,
        activation.handshake_transcript_hash,
        lineage.current_epoch_hash,
        OperatorRekeyReason::Manual,
    )
    .unwrap();

    // Fresh nonce/source, but sealed with the now-superseded epoch-0 key.
    // Generic Session::open would accept it during grace; authority rekey must not.
    let forged_previous_key = seal_message_with_key(
        &epoch2,
        PAYLOAD_TYPE_OPERATOR_REKEY,
        OLD_KEY,
        [0x22; 8],
    );
    assert!(receive_and_commit_operator_rekey(
        &mut receiver,
        &mut current_key,
        &mut lineage,
        &activation,
        &selected,
        &binding,
        &REKEY_ROOT,
        &forged_previous_key,
    )
    .is_err());

    assert_eq!(lineage, epoch1_lineage);
    assert_eq!(*current_key, epoch1_key);
    assert_eq!(receiver.session_fingerprint(23).unwrap(), epoch1_fingerprint);
    assert_eq!(receiver.nonce_counter(), epoch1_nonce);

    // Demonstrate the distinction explicitly: the generic session still accepts
    // the superseded-key envelope during grace, but the authority rekey handler
    // rejected it before entering the live replay window.
    assert!(receiver.open(&forged_previous_key).is_ok());

    // The same exact epoch-2 context under the current key is accepted.
    let current_key_envelope = seal_message_with_key(
        &epoch2,
        PAYLOAD_TYPE_OPERATOR_REKEY,
        epoch1_key,
        [0x22; 8],
    );
    receive_and_commit_operator_rekey(
        &mut receiver,
        &mut current_key,
        &mut lineage,
        &activation,
        &selected,
        &binding,
        &REKEY_ROOT,
        &current_key_envelope,
    )
    .unwrap();
    assert_eq!(lineage.key_epoch, 2);
    assert_ne!(*current_key, epoch1_key);
}