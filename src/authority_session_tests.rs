// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;
use crate::authority_negotiation::causal_authority_draft04_capability;
use crate::handshake_v2_contract::compose_v5_context;
use crate::negotiated_context::{CapabilityOfferEntryV1, negotiate_capabilities};
#[cfg(feature = "operator-rekey")]
use crate::operator_rekey::{
    OperatorRekeyMessage, OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY, propose,
};

const AEAD: [u8; 32] = [0x55; 32];
#[cfg(feature = "operator-rekey")]
const REKEY_ROOT: [u8; 32] = [0x35; 32];

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
    AuthenticatedNegotiatedHandshake::from_verified_v2_parts(host, viewer, base_v4, v5, schedule)
        .unwrap()
}

#[cfg(feature = "operator-rekey")]
fn authority_session() -> NegotiatedAuthoritySession {
    let installed = proof()
        .install_into(Session::with_source_id([0x31; 8], 9))
        .unwrap();
    let policy =
        NegotiationPolicyV1::minimum_required([causal_authority_draft04_capability()]).unwrap();
    installed.narrow_to_causal_authority(&policy).unwrap()
}

#[cfg(feature = "operator-rekey")]
fn seal_operator(message: &OperatorRekeyMessage, key: [u8; 32], source_id: [u8; 8]) -> Vec<u8> {
    let mut sender = Session::with_source_id(source_id, 7);
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
fn live_facade_accepts_only_sealed_operator_proposal_and_returns_new_key_ack() {
    let mut authority = authority_session();
    let before = authority.session().session_fingerprint(19).unwrap();
    let proposal = propose(
        1,
        authority.activation_receipt().handshake_transcript_hash,
        authority.lineage().current_epoch_hash,
        OperatorRekeyReason::Interval,
    )
    .unwrap();

    let envelope = seal_operator(&proposal, AEAD, [0x41; 8]);
    let accepted = authority.receive_operator_rekey_proposal(&envelope).unwrap();
    assert_eq!(authority.lineage().key_epoch, 1);
    assert_eq!(authority.session().nonce_counter(), 1);
    assert_ne!(before, authority.session().session_fingerprint(19).unwrap());
    assert_eq!(accepted.lineage(), authority.lineage());

    let new_key = crate::operator_rekey::derive_operator_rekey_key(
        &REKEY_ROOT,
        &authority.lineage().current_epoch_hash,
    );
    let mut ack_receiver = Session::new();
    ack_receiver.install_key(new_key);
    let plaintext = ack_receiver.open(accepted.sealed_ack()).unwrap();
    assert_eq!(
        OperatorRekeyMessage::decode(&plaintext).unwrap(),
        OperatorRekeyMessage::Ack {
            key_epoch: 1,
            epoch_hash: authority.lineage().current_epoch_hash,
        }
    );
}

#[cfg(feature = "operator-rekey")]
#[test]
fn live_facade_rejects_previous_grace_key_for_next_rekey_epoch() {
    let mut authority = authority_session();

    let epoch1 = propose(
        1,
        authority.activation_receipt().handshake_transcript_hash,
        authority.lineage().current_epoch_hash,
        OperatorRekeyReason::Interval,
    )
    .unwrap();
    let epoch1_envelope = seal_operator(&epoch1, AEAD, [0x51; 8]);
    authority
        .receive_operator_rekey_proposal(&epoch1_envelope)
        .unwrap();

    let epoch1_lineage = *authority.lineage();
    let epoch1_fingerprint = authority.session().session_fingerprint(29).unwrap();
    let epoch1_nonce = authority.session().nonce_counter();
    let epoch1_key = crate::operator_rekey::derive_operator_rekey_key(
        &REKEY_ROOT,
        &authority.lineage().current_epoch_hash,
    );

    let epoch2 = propose(
        2,
        authority.activation_receipt().handshake_transcript_hash,
        authority.lineage().current_epoch_hash,
        OperatorRekeyReason::Manual,
    )
    .unwrap();

    // The initial key is still in Session's generic grace set after epoch 1,
    // but authority-changing control must require the exact current key.
    let forged_previous_key = seal_operator(&epoch2, AEAD, [0x52; 8]);
    assert!(authority
        .receive_operator_rekey_proposal(&forged_previous_key)
        .is_err());
    assert_eq!(*authority.lineage(), epoch1_lineage);
    assert_eq!(
        authority.session().session_fingerprint(29).unwrap(),
        epoch1_fingerprint
    );
    assert_eq!(authority.session().nonce_counter(), epoch1_nonce);

    // The same canonical epoch-2 Proposal under the exact current key succeeds.
    let current_key_envelope = seal_operator(&epoch2, epoch1_key, [0x52; 8]);
    authority
        .receive_operator_rekey_proposal(&current_key_envelope)
        .unwrap();
    assert_eq!(authority.lineage().key_epoch, 2);
    assert_ne!(
        authority.session().session_fingerprint(29).unwrap(),
        epoch1_fingerprint
    );
}