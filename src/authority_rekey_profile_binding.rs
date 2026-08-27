// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Pin one rekey protocol domain to an authority activation lineage.
//!
//! A contiguous hash chain is not by itself permission to switch from Xenia's
//! lane/session rekey semantics to the distinct operator-channel rekey semantics
//! (or vice versa). Consequential session state should create one profile binding
//! at activation and require every accepted transition to match it.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_transition_evidence::{
    AuthorityRekeyTransitionEvidenceError, AuthorityRekeyTransitionEvidenceV1,
    RekeyTransitionProfileV1, advance_lineage_after_verified_transition,
};

/// Domain separator for the profile binding identity.
pub const AUTHORITY_REKEY_PROFILE_BINDING_V1_DOMAIN: &[u8] =
    b"xenia.authority-rekey-profile-binding.v1\0";
/// Profile-binding schema version.
pub const AUTHORITY_REKEY_PROFILE_BINDING_SCHEMA_VERSION: u8 = 1;

/// Immutable local choice of rekey domain for one authority activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRekeyProfileBindingV1 {
    /// Binding schema version.
    pub schema_version: u8,
    /// Session lineage being constrained.
    pub lineage_id: [u8; 32],
    /// Local activation being constrained.
    pub activation_id: [u8; 32],
    /// The only rekey context domain accepted for this activation.
    pub profile: RekeyTransitionProfileV1,
    /// SHA-256 identity of this immutable binding.
    pub binding_id: [u8; 32],
}

impl AuthorityRekeyProfileBindingV1 {
    /// Pin a rekey profile to an existing authority activation.
    pub fn new(
        activation: &AuthorityActivationReceiptV1,
        profile: RekeyTransitionProfileV1,
    ) -> Result<Self, AuthorityRekeyProfileBindingError> {
        require_nonzero(&activation.lineage_id)?;
        require_nonzero(&activation.activation_id)?;
        let binding_id = binding_id(&activation.lineage_id, &activation.activation_id, profile);
        Ok(Self {
            schema_version: AUTHORITY_REKEY_PROFILE_BINDING_SCHEMA_VERSION,
            lineage_id: activation.lineage_id,
            activation_id: activation.activation_id,
            profile,
            binding_id,
        })
    }

    /// Validate a deserialized binding against its activation receipt.
    pub fn validate(
        &self,
        activation: &AuthorityActivationReceiptV1,
    ) -> Result<(), AuthorityRekeyProfileBindingError> {
        if self.schema_version != AUTHORITY_REKEY_PROFILE_BINDING_SCHEMA_VERSION {
            return Err(AuthorityRekeyProfileBindingError::UnsupportedSchemaVersion);
        }
        if self.lineage_id != activation.lineage_id || self.activation_id != activation.activation_id {
            return Err(AuthorityRekeyProfileBindingError::ActivationMismatch);
        }
        require_nonzero(&self.lineage_id)?;
        require_nonzero(&self.activation_id)?;
        let expected = binding_id(&self.lineage_id, &self.activation_id, self.profile);
        if self.binding_id != expected {
            return Err(AuthorityRekeyProfileBindingError::BindingIdMismatch);
        }
        Ok(())
    }

    /// Canonical fixed-width binding bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            AUTHORITY_REKEY_PROFILE_BINDING_V1_DOMAIN.len() + 1 + 32 + 32 + 1,
        );
        out.extend_from_slice(AUTHORITY_REKEY_PROFILE_BINDING_V1_DOMAIN);
        out.push(self.schema_version);
        out.extend_from_slice(&self.lineage_id);
        out.extend_from_slice(&self.activation_id);
        out.push(self.profile as u8);
        out
    }
}

/// Preferred profile-pinned authority-lineage advancement path.
///
/// The underlying rekey proposal must already have passed Xenia's real
/// cryptographic/protocol verifier. This additionally proves the public context
/// is self-consistent, rooted in this activation, contiguous with the local
/// chain, and in the one rekey domain selected for this activation.
pub fn advance_profile_bound_lineage_after_verified_transition(
    lineage: &AuthorityLineageEpochEvidenceV1,
    activation: &AuthorityActivationReceiptV1,
    profile_binding: &AuthorityRekeyProfileBindingV1,
    transition: &AuthorityRekeyTransitionEvidenceV1,
) -> Result<AuthorityLineageEpochEvidenceV1, AuthorityRekeyProfileBindingError> {
    profile_binding.validate(activation)?;
    if lineage.lineage_id != profile_binding.lineage_id
        || lineage.activation_id != profile_binding.activation_id
    {
        return Err(AuthorityRekeyProfileBindingError::LineageMismatch);
    }
    if transition.profile != profile_binding.profile {
        return Err(AuthorityRekeyProfileBindingError::ProfileSwitch);
    }
    advance_lineage_after_verified_transition(lineage, activation, transition)
        .map_err(AuthorityRekeyProfileBindingError::Transition)
}

fn binding_id(
    lineage_id: &[u8; 32],
    activation_id: &[u8; 32],
    profile: RekeyTransitionProfileV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_REKEY_PROFILE_BINDING_V1_DOMAIN);
    hasher.update(lineage_id);
    hasher.update(activation_id);
    hasher.update([profile as u8]);
    hasher.finalize().into()
}

fn require_nonzero(value: &[u8; 32]) -> Result<(), AuthorityRekeyProfileBindingError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(AuthorityRekeyProfileBindingError::ZeroCommitment)
    } else {
        Ok(())
    }
}

/// Failure while pinning or enforcing a rekey domain for an authority lineage.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityRekeyProfileBindingError {
    /// Binding schema version is unsupported.
    #[error("unsupported authority rekey profile binding schema version")]
    UnsupportedSchemaVersion,
    /// Required lineage/activation commitment is all zero.
    #[error("authority rekey profile binding contains an all-zero commitment")]
    ZeroCommitment,
    /// Binding does not belong to the supplied activation.
    #[error("authority rekey profile binding does not match activation")]
    ActivationMismatch,
    /// Stored binding identity does not match canonical fields.
    #[error("authority rekey profile binding id mismatch")]
    BindingIdMismatch,
    /// Current lineage does not belong to the profile binding.
    #[error("authority lineage does not match rekey profile binding")]
    LineageMismatch,
    /// A transition attempted to change rekey protocol domains mid-lineage.
    #[error("authority lineage cannot switch rekey profiles without a new activation")]
    ProfileSwitch,
    /// Transition context/continuity validation failed.
    #[error(transparent)]
    Transition(#[from] AuthorityRekeyTransitionEvidenceError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
    use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
    use crate::authority_rekey_transition_evidence::RekeyTransitionReasonV1;

    fn activation() -> AuthorityActivationReceiptV1 {
        AuthorityActivationReceiptV1 {
            schema_version: 1,
            handshake_transcript_hash: [0x11; 32],
            base_v4_context_hash: [0x22; 32],
            final_v5_context_hash: [0x33; 32],
            host_offer_hash: [0x44; 32],
            viewer_offer_hash: [0x55; 32],
            selected_context_hash: [0x66; 32],
            negotiation_binding_hash: [0x77; 32],
            local_policy_hash: [0x88; 32],
            host_identity_fingerprint: [0x99; 32],
            lineage_id: [0xaa; 32],
            activation_id: [0xbb; 32],
        }
    }

    #[test]
    fn profile_binding_rejects_mid_lineage_domain_switch() {
        let activation = activation();
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation).unwrap();
        let binding = AuthorityRekeyProfileBindingV1::new(
            &activation,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )
        .unwrap();

        let operator = AuthorityRekeyTransitionEvidenceV1::operator(
            1,
            activation.handshake_transcript_hash,
            initial.current_epoch_hash,
            RekeyTransitionReasonV1::OperatorInterval,
        )
        .unwrap();
        let epoch_one = advance_profile_bound_lineage_after_verified_transition(
            &initial,
            &activation,
            &binding,
            &operator,
        )
        .unwrap();

        let lane = AuthorityRekeyTransitionEvidenceV1::lane(
            2,
            activation.handshake_transcript_hash,
            epoch_one.current_epoch_hash,
            RekeyTransitionReasonV1::LaneManual,
        )
        .unwrap();
        assert!(matches!(
            advance_profile_bound_lineage_after_verified_transition(
                &epoch_one,
                &activation,
                &binding,
                &lane,
            ),
            Err(AuthorityRekeyProfileBindingError::ProfileSwitch)
        ));
    }

    #[test]
    fn different_profile_produces_different_binding_identity() {
        let activation = activation();
        let lane = AuthorityRekeyProfileBindingV1::new(
            &activation,
            RekeyTransitionProfileV1::LaneSessionV1,
        )
        .unwrap();
        let operator = AuthorityRekeyProfileBindingV1::new(
            &activation,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )
        .unwrap();
        assert_ne!(lane.binding_id, operator.binding_id);
    }

    #[test]
    fn deserialized_binding_must_revalidate() {
        let activation = activation();
        let binding = AuthorityRekeyProfileBindingV1::new(
            &activation,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )
        .unwrap();
        let bytes = bincode::serialize(&binding).unwrap();
        let decoded: AuthorityRekeyProfileBindingV1 = bincode::deserialize(&bytes).unwrap();
        decoded.validate(&activation).unwrap();
    }
}
