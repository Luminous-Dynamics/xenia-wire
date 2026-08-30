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
        rekey: [0x35; 32],
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

    let mut sender = Session::new();
    sender.install_key(AEAD);
    let envelope = sender
        .seal(&proposal.encode().unwrap(), PAYLOAD_TYPE_OPERATOR_REKEY)
        .unwrap();

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
