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
use crate::operator_rekey::{OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY, propose};

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

#[test]
fn cached_current_key_drift_fails_before_live_replay_or_authority_mutation() {
    let selected = selected_context();
    let activation = activation(&selected);
    let binding = AuthorityRekeyProfileBindingV1::new(
        &activation,
        &selected,
        RekeyTransitionProfileV1::OperatorChannelV1,
    )
    .unwrap();
    let mut lineage = AuthorityLineageEpochEvidenceV1::initial(&activation).unwrap();

    let proposal = propose(
        1,
        activation.handshake_transcript_hash,
        lineage.current_epoch_hash,
        OperatorRekeyReason::Manual,
    )
    .unwrap();
    let mut sender = Session::with_source_id([0x21; 8], 7);
    sender.install_key(LIVE_KEY);
    let envelope = sender
        .seal(&proposal.encode().unwrap(), PAYLOAD_TYPE_OPERATOR_REKEY)
        .unwrap();

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
