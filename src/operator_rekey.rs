// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Rekey control messages for a single-key application channel — e.g.
//! Xenia's operator sealed channel (`docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`),
//! which installs one [`crate::Session`] AEAD key at handshake and, before this
//! module existed, never rotated it for the life of a long-lived operator
//! connection.
//!
//! Unlike the multi-lane video/audio/control rekey system in xenia-peer-core
//! (`RawRekey`, one key per lane), a channel built directly on [`crate::Session`]
//! has exactly one AEAD key to rotate. [`OperatorRekeyMessage`] is the sealed
//! control payload that does it:
//!
//! 1. The initiator (the daemon/host) builds a canonical rekey-epoch context
//!    (mirrored natively as `xenia_handshake::OperatorRekeyEpochContext` in
//!    xenia-peer — this crate doesn't depend on that one, so the two are
//!    proven byte-identical by a cross-compat test rather than a shared type),
//!    hashes it, and calls [`propose`] to build the `Proposal`.
//! 2. It seals the `Proposal` under [`PAYLOAD_TYPE_OPERATOR_REKEY`] and sends
//!    it, *then* derives the new key via [`derive_operator_rekey_key`] and
//!    installs it into its own [`crate::Session`] (mirrors `xenia-peer-core`'s
//!    lane `perform_rekey`: propose under the still-current key, install
//!    after).
//! 3. The receiver calls [`verify_proposal_epoch_hash`], which independently
//!    recomputes the epoch hash from the Proposal's own fields and checks it
//!    against the value the Proposal carries. This is **not** a tamper check
//!    — the envelope is already AEAD-authenticated, so an attacker cannot
//!    forge or alter a Proposal in transit — it's a protocol
//!    self-consistency check that catches a desynced epoch counter or a
//!    confused/duplicated Proposal before a wrong key gets installed, the
//!    same rationale `xenia_handshake::RekeyEpochContextV1::epoch_hash`
//!    serves on the lane-session side. Only after that check passes does the
//!    receiver derive the new key (same [`derive_operator_rekey_key`]),
//!    install it, and seal an `Ack` under the *new* key.
//!
//! Distinguished from an application payload (e.g. a consent decision) by
//! [`PAYLOAD_TYPE_OPERATOR_REKEY`] — a distinct cleartext envelope byte so a
//! receiver can route without a wasted decrypt attempt, the same pattern
//! `xenia-peer-core`'s clipboard reverse-path and lane `RawRekey` messages use.

use serde::{Deserialize, Serialize};

use crate::WireError;

/// Payload type for operator-channel rekey control messages
/// ([`OperatorRekeyMessage`]). Distinct from `PAYLOAD_TYPE_APPLICATION_MIN`
/// (0x30), which the operator sealed channel uses for its consent-decision
/// text payload — both live in the free `0x30..=0xFF` application range (see
/// [`crate::payload_types`]).
pub const PAYLOAD_TYPE_OPERATOR_REKEY: u8 = 0x31;

/// HKDF label for deriving an operator-channel rekey epoch's AEAD key. Distinct
/// from the lane system's `xenia/rekey/aead` label (see
/// `xenia_handshake::derive_rekey_epoch_keys` in xenia-peer) so the two rekey
/// mechanisms can never derive colliding keys. Only used by
/// [`derive_operator_rekey_key`] (the `handshake`-gated helper); a native host
/// deriving keys via its own copy of the HKDF construction doesn't need this
/// constant.
#[cfg(feature = "handshake")]
const OPERATOR_REKEY_AEAD_LABEL: &[u8] = b"xenia/operator/rekey/aead";

/// Schema tag for [`OperatorRekeyEpochContext`]'s canonical bytes. MUST match
/// `xenia_handshake::OperatorRekeyEpochContext`'s schema tag byte-for-byte
/// (proven by a cross-compat test in xenia-peer's operator sealed channel test
/// suite) and MUST differ from the lane system's own
/// `"xenia-rekey-epoch-context-v1"` tag so the two contexts can never hash to
/// the same value for equal field contents.
const OPERATOR_REKEY_EPOCH_CONTEXT_SCHEMA: &str = "xenia-operator-rekey-epoch-context-v1";

/// Why an operator-channel rekey epoch was created. Bound into the hashed
/// epoch context, so variant order matters for cross-implementation hash
/// agreement even though the reason itself isn't security-relevant — it MUST
/// match `xenia_handshake::OperatorRekeyReason`'s variant order exactly
/// (bincode encodes enums by variant index, not name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorRekeyReason {
    /// Periodic time-based rotation.
    Interval,
    /// Operator/admin explicitly requested it (reserved for future use).
    Manual,
}

/// Canonical, independently-hashable context for one operator-channel rekey
/// epoch. See the module docs for why both sides compute this hash rather
/// than the receiver trusting the sender's claimed value outright.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OperatorRekeyEpochContext {
    schema: String,
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    reason: OperatorRekeyReason,
}

impl OperatorRekeyEpochContext {
    fn new(
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: OperatorRekeyReason,
    ) -> Self {
        Self {
            schema: OPERATOR_REKEY_EPOCH_CONTEXT_SCHEMA.to_string(),
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
        }
    }

    fn epoch_hash(&self) -> Result<[u8; 32], WireError> {
        let bytes = bincode::serialize(self).map_err(WireError::encode)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

/// Rekey control message sealed under [`PAYLOAD_TYPE_OPERATOR_REKEY`] on an
/// operator sealed channel. See the module docs for the full protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorRekeyMessage {
    /// Initiator proposes a new key epoch.
    Proposal {
        /// New epoch number. Epoch 0 is the key installed at handshake.
        key_epoch: u64,
        /// Original canonical handshake transcript hash (audit chain root).
        base_transcript_hash: [u8; 32],
        /// Previous rekey epoch's hash, or `base_transcript_hash` for epoch 1.
        previous_epoch_hash: [u8; 32],
        /// Trigger reason (bound into the epoch hash; see
        /// [`OperatorRekeyReason`]).
        reason: OperatorRekeyReason,
        /// Canonical rekey-epoch hash, computed by the sender from the fields
        /// above via `OperatorRekeyEpochContext::epoch_hash`. The receiver
        /// re-derives and checks this via [`verify_proposal_epoch_hash`]
        /// before trusting it.
        epoch_hash: [u8; 32],
    },
    /// Responder acknowledges it installed the proposed epoch.
    Ack {
        /// Installed epoch number.
        key_epoch: u64,
        /// Echoes the proposal's `epoch_hash` so the initiator can detect a
        /// confused/mismatched-epoch bug. Not a tamper check — the envelope
        /// already guarantees that.
        epoch_hash: [u8; 32],
    },
}

impl OperatorRekeyMessage {
    /// Canonical bincode-v1 encoding, matching the wire's existing convention
    /// for sealed payload bodies.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }

    /// Decode from bincode-v1 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// Build a `Proposal` for the given epoch, computing its own canonical
/// `epoch_hash`. The caller (the channel initiator) is responsible for
/// sending it *before* installing the new key (see module docs for the
/// propose-then-install ordering).
pub fn propose(
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    reason: OperatorRekeyReason,
) -> Result<OperatorRekeyMessage, WireError> {
    let epoch_hash = OperatorRekeyEpochContext::new(
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
    )
    .epoch_hash()?;
    Ok(OperatorRekeyMessage::Proposal {
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
        epoch_hash,
    })
}

/// Verify a received Proposal's `epoch_hash` against its own fields (protocol
/// self-consistency, not a tamper check — see the module docs). Returns the
/// verified hash on success.
pub fn verify_proposal_epoch_hash(
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    reason: OperatorRekeyReason,
    claimed_epoch_hash: [u8; 32],
) -> Result<[u8; 32], WireError> {
    let computed = OperatorRekeyEpochContext::new(
        key_epoch,
        base_transcript_hash,
        previous_epoch_hash,
        reason,
    )
    .epoch_hash()?;
    if computed != claimed_epoch_hash {
        return Err(WireError::decode(
            "operator rekey proposal epoch_hash does not match its own context",
        ));
    }
    Ok(computed)
}

/// Derive an operator-channel rekey epoch's AEAD key from a
/// [`crate::handshake::SessionKeySchedule`]'s `rekey` root and a verified
/// `epoch_hash`. Both sides call this identically — the sender right after
/// sending the `Proposal`, the receiver right after
/// [`verify_proposal_epoch_hash`] succeeds.
///
/// Requires the `handshake` feature (for
/// [`crate::handshake::derive_labeled_session_key`]). A native host that
/// already has its own copy of the same HKDF derivation (xenia-peer's
/// `xenia_handshake::derive_operator_rekey_key`) doesn't need this function
/// or the `handshake` feature at all -- see the `operator-rekey` feature doc
/// in `Cargo.toml`.
#[cfg(feature = "handshake")]
pub fn derive_operator_rekey_key(rekey_root: &[u8; 32], epoch_hash: &[u8; 32]) -> [u8; 32] {
    crate::handshake::derive_labeled_session_key(rekey_root, epoch_hash, OPERATOR_REKEY_AEAD_LABEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_round_trips_through_bincode() {
        let msg = propose(3, [0x11; 32], [0x22; 32], OperatorRekeyReason::Interval).unwrap();
        let bytes = msg.encode().unwrap();
        assert_eq!(OperatorRekeyMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn ack_round_trips_through_bincode() {
        let msg = OperatorRekeyMessage::Ack {
            key_epoch: 3,
            epoch_hash: [0x33; 32],
        };
        let bytes = msg.encode().unwrap();
        assert_eq!(OperatorRekeyMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(OperatorRekeyMessage::decode(&[0xff; 4]).is_err());
    }

    #[test]
    fn payload_type_is_distinct_from_application_min() {
        assert_ne!(
            PAYLOAD_TYPE_OPERATOR_REKEY,
            crate::payload_types::PAYLOAD_TYPE_APPLICATION_MIN
        );
    }

    #[test]
    fn propose_then_verify_round_trips() {
        let OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        } = propose(1, [0xaa; 32], [0xbb; 32], OperatorRekeyReason::Manual).unwrap()
        else {
            unreachable!()
        };
        let verified = verify_proposal_epoch_hash(
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        )
        .unwrap();
        assert_eq!(verified, epoch_hash);
    }

    #[test]
    fn verify_rejects_a_tampered_epoch_hash() {
        let OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            ..
        } = propose(1, [0xaa; 32], [0xbb; 32], OperatorRekeyReason::Manual).unwrap()
        else {
            unreachable!()
        };
        let wrong_hash = [0xff; 32];
        assert!(
            verify_proposal_epoch_hash(
                key_epoch,
                base_transcript_hash,
                previous_epoch_hash,
                reason,
                wrong_hash,
            )
            .is_err()
        );
    }

    #[test]
    fn verify_rejects_a_desynced_epoch_number() {
        let msg = propose(1, [0xaa; 32], [0xbb; 32], OperatorRekeyReason::Manual).unwrap();
        let OperatorRekeyMessage::Proposal {
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
            ..
        } = msg
        else {
            unreachable!()
        };
        // Same epoch_hash, but claiming a different key_epoch than it was
        // computed for -- must be rejected even though the hash bytes match
        // something (just not this reconstructed context).
        assert!(
            verify_proposal_epoch_hash(
                2,
                base_transcript_hash,
                previous_epoch_hash,
                reason,
                epoch_hash,
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(feature = "handshake")]
    fn different_epochs_derive_different_keys() {
        let root = [0x42; 32];
        let hash_a = propose(1, [0; 32], [0; 32], OperatorRekeyReason::Interval)
            .unwrap()
            .encode()
            .unwrap();
        let hash_b = propose(2, [0; 32], [0; 32], OperatorRekeyReason::Interval)
            .unwrap()
            .encode()
            .unwrap();
        assert_ne!(hash_a, hash_b);
        let OperatorRekeyMessage::Proposal {
            epoch_hash: eh_a, ..
        } = OperatorRekeyMessage::decode(&hash_a).unwrap()
        else {
            unreachable!()
        };
        let OperatorRekeyMessage::Proposal {
            epoch_hash: eh_b, ..
        } = OperatorRekeyMessage::decode(&hash_b).unwrap()
        else {
            unreachable!()
        };
        assert_ne!(
            derive_operator_rekey_key(&root, &eh_a),
            derive_operator_rekey_key(&root, &eh_b)
        );
    }
}
