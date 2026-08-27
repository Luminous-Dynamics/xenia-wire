// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Pin one rekey protocol domain to an authority activation lineage.
//!
//! A contiguous hash chain is not by itself permission to switch from Xenia's
//! lane/session rekey semantics to the distinct operator-channel rekey semantics
//! (or vice versa). The binding is also constrained by the selected capability
//! context committed by the activation receipt: an operator-channel binding can
//! exist only when exact `xenia.operator-rekey / v1` was selected.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_activation_evidence::AuthorityActivationReceiptV1;
use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_transition_evidence::{
    AuthorityRekeyTransitionEvidenceError, AuthorityRekeyTransitionEvidenceV1,
    RekeyTransitionProfileV1, advance_lineage_after_verified_transition,
};
use crate::negotiated_context::NegotiatedContextV1;

/// Domain separator for the profile binding identity.
pub const AUTHORITY_REKEY_PROFILE_BINDING_V1_DOMAIN: &[u8] =
    b"xenia.authority-rekey-profile-binding.v1\0";
/// Profile-binding schema version.
pub const AUTHORITY_REKEY_PROFILE_BINDING_SCHEMA_VERSION: u8 = 1;
/// Exact negotiated capability required before operator-channel rekey may be used.
pub const OPERATOR_REKEY_CAPABILITY_NAME: &[u8] = b"xenia.operator-rekey";
/// Exact operator-rekey capability version supported by this binding profile.
pub const OPERATOR_REKEY_CAPABILITY_VERSION: &[u8] = b"v1";

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
    /// Pin a rekey profile to an activation and the exact selected capability
    /// context committed by that activation.
    ///
    /// For [`RekeyTransitionProfileV1::OperatorChannelV1`], exact
    /// `xenia.operator-rekey / v1` must be present. This prevents local code
    /// from enabling an operator rekey protocol that the authenticated
    /// negotiation never selected.
    pub fn new(
        activation: &AuthorityActivationReceiptV1,
        selected_context: &NegotiatedContextV1,
        profile: RekeyTransitionProfileV1,
    ) -> Result<Self, AuthorityRekeyProfileBindingError> {
        validate_selected_context(activation, selected_context, profile)?;
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

    /// Validate a persisted binding against both its activation receipt and the
    /// selected capability context committed by that activation.
    ///
    /// Callers loading untrusted/persisted evidence must use this method before
    /// treating the binding as an authority-session invariant.
    pub fn validate(
        &self,
        activation: &AuthorityActivationReceiptV1,
        selected_context: &NegotiatedContextV1,
    ) -> Result<(), AuthorityRekeyProfileBindingError> {
        if self.schema_version != AUTHORITY_REKEY_PROFILE_BINDING_SCHEMA_VERSION {
            return Err(AuthorityRekeyProfileBindingError::UnsupportedSchemaVersion);
        }
        if self.lineage_id != activation.lineage_id || self.activation_id != activation.activation_id {
            return Err(AuthorityRekeyProfileBindingError::ActivationMismatch);
        }
        validate_selected_context(activation, selected_context, self.profile)?;
        require_nonzero(&self.lineage_id)?;
        require_nonzero(&self.activation_id)?;
        let expected = binding_id(&self.lineage_id, &self.activation_id, self.profile);
        if self.binding_id != expected {
            return Err(AuthorityRekeyProfileBindingError::BindingIdMismatch);
        }
        Ok(())
    }

    /// Canonical fixed-width binding bytes.
    ///
    /// The activation id already commits the authenticated V5 negotiation
    /// lineage. The selected-context check is nevertheless repeated explicitly
    /// at construction/validation to prevent confused local profile selection.
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

/// Preferred profile- and capability-bound authority-lineage advancement path.
///
/// The underlying rekey proposal must already have passed Xenia's real
/// cryptographic/protocol verifier. This additionally proves the public context
/// is self-consistent, rooted in this activation, contiguous with the local
/// chain, in the one rekey domain selected for this activation, and compatible
/// with the selected capability set committed by the handshake activation.
pub fn advance_profile_bound_lineage_after_verified_transition(
    lineage: &AuthorityLineageEpochEvidenceV1,
    activation: &AuthorityActivationReceiptV1,
    selected_context: &NegotiatedContextV1,
    profile_binding: &AuthorityRekeyProfileBindingV1,
    transition: &AuthorityRekeyTransitionEvidenceV1,
) -> Result<AuthorityLineageEpochEvidenceV1, AuthorityRekeyProfileBindingError> {
    profile_binding.validate(activation, selected_context)?;
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

fn validate_selected_context(
    activation: &AuthorityActivationReceiptV1,
    selected_context: &NegotiatedContextV1,
    profile: RekeyTransitionProfileV1,
) -> Result<(), AuthorityRekeyProfileBindingError> {
    if selected_context.hash() != activation.selected_context_hash {
        return Err(AuthorityRekeyProfileBindingError::SelectedContextMismatch);
    }
    if profile == RekeyTransitionProfileV1::OperatorChannelV1
        && !selected_context.contains(
            OPERATOR_REKEY_CAPABILITY_NAME,
            OPERATOR_REKEY_CAPABILITY_VERSION,
        )
    {
        return Err(AuthorityRekeyProfileBindingError::OperatorRekeyNotNegotiated);
    }
    Ok(())
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
    /// Supplied selected context does not match the selected-context commitment
    /// carried by the activation receipt.
    #[error("selected capability context does not match authority activation")]
    SelectedContextMismatch,
    /// Operator-channel rekey was requested without exact negotiated
    /// `xenia.operator-rekey / v1` support.
    #[error("operator rekey v1 was not selected by authenticated capability negotiation")]
    OperatorRekeyNotNegotiated,
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
    use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
    use crate::authority_rekey_transition_evidence::RekeyTransitionReasonV1;
    use crate::negotiated_context::NegotiatedCapabilityV1;

    fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
        NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
    }

    fn selected_with_operator() -> NegotiatedContextV1 {
        NegotiatedContextV1::from_capabilities([
            cap(b"xenia.causal-authority", b"draft-04"),
            cap(OPERATOR_REKEY_CAPABILITY_NAME, OPERATOR_REKEY_CAPABILITY_VERSION),
        ])
        .unwrap()
    }

    fn selected_without_operator() -> NegotiatedContextV1 {
        NegotiatedContextV1::from_capabilities([
            cap(b"xenia.causal-authority", b"draft-04"),
        ])
        .unwrap()
    }

    fn activation(selected_context: &NegotiatedContextV1) -> AuthorityActivationReceiptV1 {
        AuthorityActivationReceiptV1 {
            schema_version: 1,
            handshake_transcript_hash: [0x11; 32],
            base_v4_context_hash: [0x22; 32],
            final_v5_context_hash: [0x33; 32],
            host_offer_hash: [0x44; 32],
            viewer_offer_hash: [0x55; 32],
            selected_context_hash: selected_context.hash(),
            negotiation_binding_hash: [0x77; 32],
            local_policy_hash: [0x88; 32],
            host_identity_fingerprint: [0x99; 32],
            lineage_id: [0xaa; 32],
            activation_id: [0xbb; 32],
        }
    }

    #[test]
    fn operator_profile_requires_exact_negotiated_operator_rekey_v1() {
        let no_operator = selected_without_operator();
        let activation = activation(&no_operator);
        assert!(matches!(
            AuthorityRekeyProfileBindingV1::new(
                &activation,
                &no_operator,
                RekeyTransitionProfileV1::OperatorChannelV1,
            ),
            Err(AuthorityRekeyProfileBindingError::OperatorRekeyNotNegotiated)
        ));

        let wrong_version = NegotiatedContextV1::from_capabilities([
            cap(b"xenia.causal-authority", b"draft-04"),
            cap(OPERATOR_REKEY_CAPABILITY_NAME, b"v0"),
        ])
        .unwrap();
        let activation = activation(&wrong_version);
        assert!(matches!(
            AuthorityRekeyProfileBindingV1::new(
                &activation,
                &wrong_version,
                RekeyTransitionProfileV1::OperatorChannelV1,
            ),
            Err(AuthorityRekeyProfileBindingError::OperatorRekeyNotNegotiated)
        ));
    }

    #[test]
    fn selected_context_must_match_activation_commitment() {
        let selected = selected_with_operator();
        let activation = activation(&selected);
        let different = selected_without_operator();
        assert!(matches!(
            AuthorityRekeyProfileBindingV1::new(
                &activation,
                &different,
                RekeyTransitionProfileV1::LaneSessionV1,
            ),
            Err(AuthorityRekeyProfileBindingError::SelectedContextMismatch)
        ));
    }

    #[test]
    fn profile_binding_rejects_mid_lineage_domain_switch() {
        let selected = selected_with_operator();
        let activation = activation(&selected);
        let initial = AuthorityLineageEpochEvidenceV1::initial(&activation).unwrap();
        let binding = AuthorityRekeyProfileBindingV1::new(
            &activation,
            &selected,
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
            &selected,
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
                &selected,
                &binding,
                &lane,
            ),
            Err(AuthorityRekeyProfileBindingError::ProfileSwitch)
        ));
    }

    #[test]
    fn persisted_binding_revalidates_and_profile_changes_identity() {
        let selected = selected_with_operator();
        let activation = activation(&selected);
        let operator = AuthorityRekeyProfileBindingV1::new(
            &activation,
            &selected,
            RekeyTransitionProfileV1::OperatorChannelV1,
        )
        .unwrap();
        let lane = AuthorityRekeyProfileBindingV1::new(
            &activation,
            &selected,
            RekeyTransitionProfileV1::LaneSessionV1,
        )
        .unwrap();
        assert_ne!(operator.binding_id, lane.binding_id);

        let bytes = bincode::serialize(&operator).unwrap();
        let decoded: AuthorityRekeyProfileBindingV1 = bincode::deserialize(&bytes).unwrap();
        decoded.validate(&activation, &selected).unwrap();
    }

    #[test]
    fn lane_profile_does_not_require_operator_capability() {
        let selected = selected_without_operator();
        let activation = activation(&selected);
        AuthorityRekeyProfileBindingV1::new(
            &activation,
            &selected,
            RekeyTransitionProfileV1::LaneSessionV1,
        )
        .unwrap();
    }
}
