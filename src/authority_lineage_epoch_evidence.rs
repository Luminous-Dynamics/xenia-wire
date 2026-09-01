// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Durable evidence that one negotiated authority activation remains attached to
//! the same authenticated Xenia rekey lineage as the existing epoch chain
//! advances.
//!
//! This module does not verify rekey cryptography and does not derive keys. It
//! records the already-verified epoch-chain facts and enforces strict continuity
//! so evidence cannot silently jump between epochs or lineages.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_activation_evidence::AuthorityActivationReceiptV1;

/// Schema version encoded into canonical epoch-evidence bytes.
pub const AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION: u8 = 1;
/// Domain separator for canonical lineage-epoch evidence bytes.
pub const AUTHORITY_LINEAGE_EPOCH_V1_DOMAIN: &[u8] = b"xenia.authority-lineage-epoch-evidence.v1\0";

/// Durable view of one point in an authority-capable Xenia rekey lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLineageEpochEvidenceV1 {
    /// Evidence schema version.
    pub schema_version: u8,
    /// Stable public session-lineage identifier from the activation receipt.
    pub lineage_id: [u8; 32],
    /// Local policy-bound activation identity from the activation receipt.
    pub activation_id: [u8; 32],
    /// Current Xenia key epoch. Epoch 0 is the authenticated handshake root.
    pub key_epoch: u64,
    /// Previous verified epoch-chain hash. At epoch 0 this is the handshake transcript hash.
    pub previous_epoch_hash: [u8; 32],
    /// Current verified epoch-chain head. At epoch 0 this is the handshake transcript hash.
    pub current_epoch_hash: [u8; 32],
}

impl AuthorityLineageEpochEvidenceV1 {
    /// Create epoch-0 evidence from a negotiated authority activation receipt.
    pub fn initial(
        activation: &AuthorityActivationReceiptV1,
    ) -> Result<Self, AuthorityLineageEpochEvidenceError> {
        require_nonzero(&activation.lineage_id)?;
        require_nonzero(&activation.activation_id)?;
        require_nonzero(&activation.handshake_transcript_hash)?;
        Ok(Self {
            schema_version: AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION,
            lineage_id: activation.lineage_id,
            activation_id: activation.activation_id,
            key_epoch: 0,
            previous_epoch_hash: activation.handshake_transcript_hash,
            current_epoch_hash: activation.handshake_transcript_hash,
        })
    }

    /// Advance evidence after the existing Xenia rekey path has cryptographically
    /// verified and accepted the next epoch.
    ///
    /// This helper intentionally accepts only already-verified epoch-chain facts.
    /// It does not authenticate proposals, derive keys, or replace the existing
    /// rekey protocol.
    pub fn advance_after_verified_rekey(
        &self,
        next_epoch: u64,
        previous_epoch_hash: [u8; 32],
        current_epoch_hash: [u8; 32],
    ) -> Result<Self, AuthorityLineageEpochEvidenceError> {
        if self.schema_version != AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION {
            return Err(AuthorityLineageEpochEvidenceError::UnsupportedSchemaVersion);
        }
        let expected_epoch = self
            .key_epoch
            .checked_add(1)
            .ok_or(AuthorityLineageEpochEvidenceError::EpochOverflow)?;
        if next_epoch != expected_epoch {
            return Err(AuthorityLineageEpochEvidenceError::NonContiguousEpoch);
        }
        if previous_epoch_hash != self.current_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::PreviousEpochHashMismatch);
        }
        require_nonzero(&current_epoch_hash)?;
        if current_epoch_hash == previous_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::UnchangedEpochHash);
        }

        Ok(Self {
            schema_version: AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION,
            lineage_id: self.lineage_id,
            activation_id: self.activation_id,
            key_epoch: next_epoch,
            previous_epoch_hash,
            current_epoch_hash,
        })
    }

    /// Canonical fixed-width evidence bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(AUTHORITY_LINEAGE_EPOCH_V1_DOMAIN.len() + 1 + 32 + 32 + 8 + 32 + 32);
        out.extend_from_slice(AUTHORITY_LINEAGE_EPOCH_V1_DOMAIN);
        out.push(self.schema_version);
        out.extend_from_slice(&self.lineage_id);
        out.extend_from_slice(&self.activation_id);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.previous_epoch_hash);
        out.extend_from_slice(&self.current_epoch_hash);
        out
    }

    /// SHA-256 digest of the canonical epoch evidence.
    pub fn evidence_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Validate the shape of deserialized evidence without advancing it.
    pub fn validate(&self) -> Result<(), AuthorityLineageEpochEvidenceError> {
        if self.schema_version != AUTHORITY_LINEAGE_EPOCH_SCHEMA_VERSION {
            return Err(AuthorityLineageEpochEvidenceError::UnsupportedSchemaVersion);
        }
        require_nonzero(&self.lineage_id)?;
        require_nonzero(&self.activation_id)?;
        require_nonzero(&self.previous_epoch_hash)?;
        require_nonzero(&self.current_epoch_hash)?;
        if self.key_epoch == 0 && self.previous_epoch_hash != self.current_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::InvalidInitialEpoch);
        }
        if self.key_epoch > 0 && self.previous_epoch_hash == self.current_epoch_hash {
            return Err(AuthorityLineageEpochEvidenceError::UnchangedEpochHash);
        }
        Ok(())
    }
}

fn require_nonzero(value: &[u8; 32]) -> Result<(), AuthorityLineageEpochEvidenceError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(AuthorityLineageEpochEvidenceError::ZeroCommitment)
    } else {
        Ok(())
    }
}

/// Failure while constructing or validating authority-lineage epoch evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityLineageEpochEvidenceError {
    /// Evidence schema version is unsupported.
    #[error("unsupported authority lineage epoch evidence schema version")]
    UnsupportedSchemaVersion,
    /// Epoch increment overflowed u64.
    #[error("authority lineage key epoch overflow")]
    EpochOverflow,
    /// Next epoch was not exactly current+1.
    #[error("authority lineage rekey epoch is not contiguous")]
    NonContiguousEpoch,
    /// Rekey evidence does not point back to the locally expected chain head.
    #[error("authority lineage previous epoch hash does not match local chain head")]
    PreviousEpochHashMismatch,
    /// Required commitment is the all-zero sentinel.
    #[error("authority lineage epoch evidence contains an all-zero commitment")]
    ZeroCommitment,
    /// Accepted rekey did not change the epoch-chain hash.
    #[error("authority lineage rekey must advance to a distinct epoch hash")]
    UnchangedEpochHash,
    /// Epoch-0 evidence does not use the same handshake root as previous/current hash.
    #[error("authority lineage epoch-0 evidence has inconsistent handshake root")]
    InvalidInitialEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_activation_evidence::derive_authority_activation_receipt;
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

    fn activation_receipt() -> AuthorityActivationReceiptV1 {
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn epoch_zero_is_rooted_in_authenticated_handshake() {
        let evidence = AuthorityLineageEpochEvidenceV1::initial(&activation_receipt()).unwrap();
        assert_eq!(evidence.key_epoch, 0);
        assert_eq!(evidence.previous_epoch_hash, [0x11; 32]);
        assert_eq!(evidence.current_epoch_hash, [0x11; 32]);
        assert_eq!(evidence.canonical_bytes().len(), 179);
        assert_eq!(
            hex(&evidence.evidence_digest()),
            "47eb22fe9ff6baf4b1a9b64c6643a2f08e3de67c4c17411710f57a17fed423af"
        );
    }

    #[test]
    fn verified_rekey_preserves_lineage_and_activation() {
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation_receipt()).unwrap();
        let next = initial
            .advance_after_verified_rekey(1, [0x11; 32], [0x66; 32])
            .unwrap();
        assert_eq!(next.lineage_id, initial.lineage_id);
        assert_eq!(next.activation_id, initial.activation_id);
        assert_eq!(next.key_epoch, 1);
        assert_eq!(
            hex(&next.evidence_digest()),
            "4d2bcc3eec6d1b8e3c9fb56b329865ab73b45ca1099f52262d55a2e4adf7ad52"
        );
    }

    #[test]
    fn skipped_wrong_parent_and_noop_rekeys_fail_closed() {
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation_receipt()).unwrap();
        assert_eq!(
            initial
                .advance_after_verified_rekey(2, [0x11; 32], [0x66; 32])
                .unwrap_err(),
            AuthorityLineageEpochEvidenceError::NonContiguousEpoch
        );
        assert_eq!(
            initial
                .advance_after_verified_rekey(1, [0x77; 32], [0x66; 32])
                .unwrap_err(),
            AuthorityLineageEpochEvidenceError::PreviousEpochHashMismatch
        );
        assert_eq!(
            initial
                .advance_after_verified_rekey(1, [0x11; 32], [0x11; 32])
                .unwrap_err(),
            AuthorityLineageEpochEvidenceError::UnchangedEpochHash
        );
    }

    #[test]
    fn malformed_deserialized_initial_epoch_is_rejected() {
        let mut evidence = AuthorityLineageEpochEvidenceV1::initial(&activation_receipt()).unwrap();
        evidence.current_epoch_hash = [0x99; 32];
        assert_eq!(
            evidence.validate().unwrap_err(),
            AuthorityLineageEpochEvidenceError::InvalidInitialEpoch
        );
    }
}
