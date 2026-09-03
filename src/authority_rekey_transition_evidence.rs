// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Self-describing evidence for one already-verified Xenia rekey transition.
//!
//! The existing rekey protocols remain authoritative. This module does not
//! authenticate a proposal, derive a key, or mutate a [`crate::Session`]. It
//! records the exact public context that the existing verifier accepted and
//! independently recomputes the protocol's historical BLAKE3 epoch hash.
//!
//! Two rekey domains exist today and are intentionally distinct:
//!
//! - lane/session rekey: `xenia-rekey-epoch-context-v1`;
//! - operator-channel rekey: `xenia-operator-rekey-epoch-context-v1`.
//!
//! A bare 32-byte epoch hash is therefore not sufficient durable evidence: the
//! receipt must also say which domain and reason produced it.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
use crate::authority_lineage_epoch_evidence::{
    AuthorityLineageEpochEvidenceError, AuthorityLineageEpochEvidenceV1,
};

/// Schema version for the public transition-evidence encoding.
pub const AUTHORITY_REKEY_TRANSITION_SCHEMA_VERSION: u8 = 1;
/// Domain separator for canonical transition-evidence bytes.
pub const AUTHORITY_REKEY_TRANSITION_V1_DOMAIN: &[u8] =
    b"xenia.authority-rekey-transition-evidence.v1\0";

const LANE_REKEY_CONTEXT_SCHEMA: &str = "xenia-rekey-epoch-context-v1";
const OPERATOR_REKEY_CONTEXT_SCHEMA: &str = "xenia-operator-rekey-epoch-context-v1";

/// Exact historical rekey hash domain represented by a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RekeyTransitionProfileV1 {
    /// Multi-lane/session rekey context used by `xenia-handshake`.
    LaneSessionV1 = 1,
    /// Single-key operator-channel rekey context used by `operator_rekey`.
    OperatorChannelV1 = 2,
}

/// Exact semantic reason for a rekey transition.
///
/// The public discriminants are evidence codes, not bincode enum indices. The
/// private compatibility mirrors below preserve each historical protocol's
/// actual bincode variant order when recomputing `epoch_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RekeyTransitionReasonV1 {
    /// Lane/session operator-initiated rekey.
    LaneManual = 1,
    /// Lane/session frame-count threshold.
    LaneFrameCount = 2,
    /// Lane/session byte-count threshold.
    LaneByteCount = 3,
    /// Lane/session time threshold.
    LaneTime = 4,
    /// Lane/session transport-context change.
    LaneTransportChange = 5,
    /// Operator-channel periodic rotation.
    OperatorInterval = 16,
    /// Operator-channel explicit/manual rotation.
    OperatorManual = 17,
}

impl RekeyTransitionReasonV1 {
    fn profile(self) -> RekeyTransitionProfileV1 {
        match self {
            Self::LaneManual
            | Self::LaneFrameCount
            | Self::LaneByteCount
            | Self::LaneTime
            | Self::LaneTransportChange => RekeyTransitionProfileV1::LaneSessionV1,
            Self::OperatorInterval | Self::OperatorManual => {
                RekeyTransitionProfileV1::OperatorChannelV1
            }
        }
    }
}

/// Durable public context for one rekey transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRekeyTransitionEvidenceV1 {
    /// Evidence schema version.
    pub schema_version: u8,
    /// Rekey hash domain/profile.
    pub profile: RekeyTransitionProfileV1,
    /// Exact semantic rekey reason.
    pub reason: RekeyTransitionReasonV1,
    /// New epoch number. Epoch zero is reserved for the handshake root.
    pub key_epoch: u64,
    /// Original authenticated handshake transcript hash.
    pub base_transcript_hash: [u8; 32],
    /// Previous accepted epoch hash, or the handshake transcript for epoch one.
    pub previous_epoch_hash: [u8; 32],
    /// Exact BLAKE3 epoch hash recomputed from the historical protocol context.
    pub epoch_hash: [u8; 32],
}

impl AuthorityRekeyTransitionEvidenceV1 {
    /// Construct lane/session transition evidence and recompute the exact
    /// `xenia_handshake::RekeyEpochContextV1::epoch_hash` value.
    pub fn lane(
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyTransitionReasonV1,
    ) -> Result<Self, AuthorityRekeyTransitionEvidenceError> {
        if reason.profile() != RekeyTransitionProfileV1::LaneSessionV1 {
            return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch);
        }
        Self::new(
            RekeyTransitionProfileV1::LaneSessionV1,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
        )
    }

    /// Construct operator-channel transition evidence and recompute the exact
    /// `operator_rekey` proposal epoch hash.
    pub fn operator(
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyTransitionReasonV1,
    ) -> Result<Self, AuthorityRekeyTransitionEvidenceError> {
        if reason.profile() != RekeyTransitionProfileV1::OperatorChannelV1 {
            return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch);
        }
        Self::new(
            RekeyTransitionProfileV1::OperatorChannelV1,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
        )
    }

    fn new(
        profile: RekeyTransitionProfileV1,
        reason: RekeyTransitionReasonV1,
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
    ) -> Result<Self, AuthorityRekeyTransitionEvidenceError> {
        if key_epoch == 0 {
            return Err(AuthorityRekeyTransitionEvidenceError::ZeroRekeyEpoch);
        }
        require_nonzero(&base_transcript_hash)?;
        require_nonzero(&previous_epoch_hash)?;
        let epoch_hash = recompute_epoch_hash(
            profile,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
        )?;
        Ok(Self {
            schema_version: AUTHORITY_REKEY_TRANSITION_SCHEMA_VERSION,
            profile,
            reason,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            epoch_hash,
        })
    }

    /// Recompute and validate the exact historical epoch hash.
    pub fn validate(&self) -> Result<(), AuthorityRekeyTransitionEvidenceError> {
        if self.schema_version != AUTHORITY_REKEY_TRANSITION_SCHEMA_VERSION {
            return Err(AuthorityRekeyTransitionEvidenceError::UnsupportedSchemaVersion);
        }
        if self.key_epoch == 0 {
            return Err(AuthorityRekeyTransitionEvidenceError::ZeroRekeyEpoch);
        }
        if self.reason.profile() != self.profile {
            return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch);
        }
        require_nonzero(&self.base_transcript_hash)?;
        require_nonzero(&self.previous_epoch_hash)?;
        require_nonzero(&self.epoch_hash)?;
        let computed = recompute_epoch_hash(
            self.profile,
            self.reason,
            self.key_epoch,
            self.base_transcript_hash,
            self.previous_epoch_hash,
        )?;
        if computed != self.epoch_hash {
            return Err(AuthorityRekeyTransitionEvidenceError::EpochHashMismatch);
        }
        Ok(())
    }

    /// Canonical fixed-width public evidence bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            AUTHORITY_REKEY_TRANSITION_V1_DOMAIN.len() + 1 + 1 + 1 + 8 + 32 + 32 + 32,
        );
        out.extend_from_slice(AUTHORITY_REKEY_TRANSITION_V1_DOMAIN);
        out.push(self.schema_version);
        out.push(self.profile as u8);
        out.push(self.reason as u8);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.base_transcript_hash);
        out.extend_from_slice(&self.previous_epoch_hash);
        out.extend_from_slice(&self.epoch_hash);
        out
    }

    /// SHA-256 digest of the canonical public transition evidence.
    pub fn evidence_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

/// Advance an authority-lineage position using a self-verifying public rekey
/// context after the existing cryptographic rekey verifier has accepted it.
///
/// This function also binds the transition back to the original activation's
/// handshake root. It still does **not** authenticate a proposal by itself.
pub fn advance_lineage_after_verified_transition(
    lineage: &AuthorityLineageEpochEvidenceV1,
    activation: &AuthorityActivationReceiptV1,
    transition: &AuthorityRekeyTransitionEvidenceV1,
) -> Result<AuthorityLineageEpochEvidenceV1, AuthorityRekeyTransitionEvidenceError> {
    transition.validate()?;
    if activation.lineage_id != lineage.lineage_id
        || activation.activation_id != lineage.activation_id
    {
        return Err(AuthorityRekeyTransitionEvidenceError::ActivationLineageMismatch);
    }
    if transition.base_transcript_hash != activation.handshake_transcript_hash {
        return Err(AuthorityRekeyTransitionEvidenceError::BaseTranscriptMismatch);
    }
    lineage
        .advance_after_verified_rekey(
            transition.key_epoch,
            transition.previous_epoch_hash,
            transition.epoch_hash,
        )
        .map_err(AuthorityRekeyTransitionEvidenceError::Lineage)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum LaneRekeyReasonMirror {
    Manual,
    FrameCount,
    ByteCount,
    Time,
    TransportChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LaneRekeyContextMirror {
    schema: String,
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    reason: LaneRekeyReasonMirror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum OperatorRekeyReasonMirror {
    Interval,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OperatorRekeyContextMirror {
    schema: String,
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    reason: OperatorRekeyReasonMirror,
}

fn recompute_epoch_hash(
    profile: RekeyTransitionProfileV1,
    reason: RekeyTransitionReasonV1,
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
) -> Result<[u8; 32], AuthorityRekeyTransitionEvidenceError> {
    let bytes = match profile {
        RekeyTransitionProfileV1::LaneSessionV1 => {
            let reason = match reason {
                RekeyTransitionReasonV1::LaneManual => LaneRekeyReasonMirror::Manual,
                RekeyTransitionReasonV1::LaneFrameCount => LaneRekeyReasonMirror::FrameCount,
                RekeyTransitionReasonV1::LaneByteCount => LaneRekeyReasonMirror::ByteCount,
                RekeyTransitionReasonV1::LaneTime => LaneRekeyReasonMirror::Time,
                RekeyTransitionReasonV1::LaneTransportChange => {
                    LaneRekeyReasonMirror::TransportChange
                }
                _ => return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch),
            };
            bincode::serialize(&LaneRekeyContextMirror {
                schema: LANE_REKEY_CONTEXT_SCHEMA.to_string(),
                key_epoch,
                base_transcript_hash,
                previous_epoch_hash,
                reason,
            })?
        }
        RekeyTransitionProfileV1::OperatorChannelV1 => {
            let reason = match reason {
                RekeyTransitionReasonV1::OperatorInterval => OperatorRekeyReasonMirror::Interval,
                RekeyTransitionReasonV1::OperatorManual => OperatorRekeyReasonMirror::Manual,
                _ => return Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch),
            };
            bincode::serialize(&OperatorRekeyContextMirror {
                schema: OPERATOR_REKEY_CONTEXT_SCHEMA.to_string(),
                key_epoch,
                base_transcript_hash,
                previous_epoch_hash,
                reason,
            })?
        }
    };
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn require_nonzero(value: &[u8; 32]) -> Result<(), AuthorityRekeyTransitionEvidenceError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(AuthorityRekeyTransitionEvidenceError::ZeroCommitment)
    } else {
        Ok(())
    }
}

/// Failure while constructing or linking public rekey transition evidence.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityRekeyTransitionEvidenceError {
    /// Evidence schema version is unsupported.
    #[error("unsupported authority rekey transition evidence schema version")]
    UnsupportedSchemaVersion,
    /// Rekey epoch zero is reserved for the authenticated handshake root.
    #[error("rekey transition epoch must be greater than zero")]
    ZeroRekeyEpoch,
    /// Required commitment was the all-zero sentinel.
    #[error("rekey transition evidence contains an all-zero commitment")]
    ZeroCommitment,
    /// Reason does not belong to the selected rekey profile/domain.
    #[error("rekey transition reason does not match its rekey profile")]
    ReasonProfileMismatch,
    /// Historical canonical rekey-context serialization failed.
    #[error("failed to encode historical rekey context: {0}")]
    Bincode(#[from] bincode::Error),
    /// Stored epoch hash does not equal the recomputed historical context hash.
    #[error("rekey transition epoch hash does not match its canonical context")]
    EpochHashMismatch,
    /// Transition was paired with a different activation/lineage.
    #[error("rekey transition activation does not match local lineage")]
    ActivationLineageMismatch,
    /// Rekey context is rooted in a different handshake transcript.
    #[error("rekey transition base transcript does not match authority activation")]
    BaseTranscriptMismatch,
    /// Existing lineage continuity checks rejected the transition.
    #[error(transparent)]
    Lineage(#[from] AuthorityLineageEpochEvidenceError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_activation_evidence::derive_authority_activation_receipt;
    use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::negotiated_context::{CapabilityOfferEntryV1, CapabilityOfferV1};
    use crate::negotiation_policy::NegotiationPolicyV1;

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn activation() -> AuthorityActivationReceiptV1 {
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
        let policy =
            NegotiationPolicyV1::minimum_required([causal_authority_draft04_capability()]).unwrap();
        derive_authority_activation_receipt(
            &host,
            &viewer,
            core::array::from_fn(|index| index as u8),
            [0x11; 32],
            [0x22; 32],
            &policy,
        )
        .unwrap()
    }

    #[test]
    fn lane_and_operator_domains_produce_distinct_hashes() {
        let lane = AuthorityRekeyTransitionEvidenceV1::lane(
            1,
            [0x11; 32],
            [0x11; 32],
            RekeyTransitionReasonV1::LaneManual,
        )
        .unwrap();
        let operator = AuthorityRekeyTransitionEvidenceV1::operator(
            1,
            [0x11; 32],
            [0x11; 32],
            RekeyTransitionReasonV1::OperatorManual,
        )
        .unwrap();
        assert_ne!(lane.epoch_hash, operator.epoch_hash);
        lane.validate().unwrap();
        operator.validate().unwrap();
    }

    #[test]
    fn transition_advances_only_matching_activation_lineage() {
        let activation = activation();
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation).unwrap();
        let transition = AuthorityRekeyTransitionEvidenceV1::operator(
            1,
            activation.handshake_transcript_hash,
            initial.current_epoch_hash,
            RekeyTransitionReasonV1::OperatorInterval,
        )
        .unwrap();
        let next =
            advance_lineage_after_verified_transition(&initial, &activation, &transition).unwrap();
        assert_eq!(next.key_epoch, 1);
        assert_eq!(next.current_epoch_hash, transition.epoch_hash);
        assert_eq!(next.lineage_id, initial.lineage_id);
        assert_eq!(next.activation_id, initial.activation_id);
    }

    #[test]
    fn tampered_or_cross_domain_evidence_fails_closed() {
        let mut transition = AuthorityRekeyTransitionEvidenceV1::lane(
            1,
            [0x11; 32],
            [0x11; 32],
            RekeyTransitionReasonV1::LaneFrameCount,
        )
        .unwrap();
        transition.epoch_hash[0] ^= 1;
        assert!(matches!(
            transition.validate(),
            Err(AuthorityRekeyTransitionEvidenceError::EpochHashMismatch)
        ));

        assert!(matches!(
            AuthorityRekeyTransitionEvidenceV1::operator(
                1,
                [0x11; 32],
                [0x11; 32],
                RekeyTransitionReasonV1::LaneManual,
            ),
            Err(AuthorityRekeyTransitionEvidenceError::ReasonProfileMismatch)
        ));
    }
}
