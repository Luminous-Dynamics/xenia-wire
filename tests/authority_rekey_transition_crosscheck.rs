// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(all(
    feature = "causal-authority",
    feature = "handshake",
    feature = "operator-rekey"
))]

use xenia_wire::authority_rekey_transition_evidence::{
    AuthorityRekeyTransitionEvidenceV1, RekeyTransitionReasonV1,
};
use xenia_wire::operator_rekey::{OperatorRekeyMessage, OperatorRekeyReason, propose};

#[test]
fn evidence_recomputes_existing_operator_rekey_epoch_hash_exactly() {
    let base = [0x11; 32];
    let previous = [0x22; 32];
    let proposal = propose(7, base, previous, OperatorRekeyReason::Manual).unwrap();
    let OperatorRekeyMessage::Proposal { epoch_hash, .. } = proposal else {
        unreachable!();
    };

    let evidence = AuthorityRekeyTransitionEvidenceV1::operator(
        7,
        base,
        previous,
        RekeyTransitionReasonV1::OperatorManual,
    )
    .unwrap();

    assert_eq!(evidence.epoch_hash, epoch_hash);
    evidence.validate().unwrap();
}
