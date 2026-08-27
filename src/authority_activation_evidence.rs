// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Durable evidence describing how dynamically negotiated causal authority was
//! activated under one local downgrade policy.
//!
//! This module deliberately does **not** authenticate handshake signatures.
//! Callers must only derive a receipt after the V2 handshake has authenticated
//! the transcript and its negotiation binding. The receipt then gives durable,
//! internally reproducible evidence for auditing and downstream execution.

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authority_negotiation::{
    AuthorityNegotiationError, require_causal_authority_draft04_evidence,
};
use crate::handshake_v2_contract::compose_v5_context;
use crate::negotiated_context::{
    CapabilityOfferV1, NegotiatedContextError, negotiate_capabilities,
};
use crate::negotiation_policy::{NegotiationPolicyError, NegotiationPolicyV1};

/// Schema version encoded into canonical receipt bytes.
pub const AUTHORITY_ACTIVATION_RECEIPT_SCHEMA_VERSION: u8 = 1;
/// Domain separator for the public cryptographic session-lineage identifier.
pub const AUTHORITY_LINEAGE_V1_DOMAIN: &[u8] = b"xenia.authority-lineage.v1\0";
/// Domain separator for local policy activation identity.
pub const AUTHORITY_ACTIVATION_V1_DOMAIN: &[u8] = b"xenia.authority-activation.v1\0";
/// Domain separator for canonical durable authority-activation receipt bytes.
pub const AUTHORITY_ACTIVATION_RECEIPT_V1_DOMAIN: &[u8] =
    b"xenia.authority-activation-receipt.v1\0";

/// Durable evidence for one dynamically negotiated authority activation.
///
/// `lineage_id` identifies the authenticated session lineage independently of
/// local policy. `activation_id` additionally binds the exact local policy that
/// accepted the negotiated result. Neither value is an authorization token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityActivationReceiptV1 {
    /// Receipt schema version. Must be exactly 1 for this structure.
    pub schema_version: u8,
    /// Hash of the successfully authenticated V2 handshake transcript.
    pub handshake_transcript_hash: [u8; 32],
    /// Existing authenticated V4 session-context commitment.
    pub base_v4_context_hash: [u8; 32],
    /// V5 = SHA-256(V5 domain || V4 || negotiation binding).
    pub final_v5_context_hash: [u8; 32],
    /// Canonical host capability-offer hash.
    pub host_offer_hash: [u8; 32],
    /// Canonical viewer capability-offer hash.
    pub viewer_offer_hash: [u8; 32],
    /// Deterministic mutually selected capability-context hash.
    pub selected_context_hash: [u8; 32],
    /// Binding over host offer, viewer offer, and deterministic selection.
    pub negotiation_binding_hash: [u8; 32],
    /// Canonical local minimum/allow-list policy hash actually enforced.
    pub local_policy_hash: [u8; 32],
    /// Fingerprint of the authenticated host signing identity.
    pub host_identity_fingerprint: [u8; 32],
    /// Public session-lineage identifier, stable across verified rekeys.
    pub lineage_id: [u8; 32],
    /// Policy-bound authority activation identity.
    pub activation_id: [u8; 32],
}

impl AuthorityActivationReceiptV1 {
    /// Canonical fixed-width receipt bytes for hashing/export.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTHORITY_ACTIVATION_RECEIPT_V1_DOMAIN.len() + 1 + 32 * 11);
        out.extend_from_slice(AUTHORITY_ACTIVATION_RECEIPT_V1_DOMAIN);
        out.push(self.schema_version);
        out.extend_from_slice(&self.handshake_transcript_hash);
        out.extend_from_slice(&self.base_v4_context_hash);
        out.extend_from_slice(&self.final_v5_context_hash);
        out.extend_from_slice(&self.host_offer_hash);
        out.extend_from_slice(&self.viewer_offer_hash);
        out.extend_from_slice(&self.selected_context_hash);
        out.extend_from_slice(&self.negotiation_binding_hash);
        out.extend_from_slice(&self.local_policy_hash);
        out.extend_from_slice(&self.host_identity_fingerprint);
        out.extend_from_slice(&self.lineage_id);
        out.extend_from_slice(&self.activation_id);
        out
    }

    /// SHA-256 identity of the complete canonical durable receipt.
    pub fn receipt_digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Re-derive all negotiation, V5, policy, lineage, and activation fields and
    /// require exact equality with this deserialized/exported receipt.
    ///
    /// This proves internal consistency only. It does not re-verify handshake
    /// signatures; the transcript hash must still come from authenticated V2
    /// handshake evidence.
    pub fn verify_internal_consistency(
        &self,
        host_offer: &CapabilityOfferV1,
        viewer_offer: &CapabilityOfferV1,
        policy: &NegotiationPolicyV1,
    ) -> Result<(), AuthorityActivationEvidenceError> {
        if self.schema_version != AUTHORITY_ACTIVATION_RECEIPT_SCHEMA_VERSION {
            return Err(AuthorityActivationEvidenceError::UnsupportedSchemaVersion);
        }
        let expected = derive_authority_activation_receipt(
            host_offer,
            viewer_offer,
            self.base_v4_context_hash,
            self.handshake_transcript_hash,
            self.host_identity_fingerprint,
            policy,
        )?;
        if expected != *self {
            return Err(AuthorityActivationEvidenceError::ReceiptMismatch);
        }
        Ok(())
    }
}

/// Derive a durable authority-activation receipt from already authenticated V2
/// handshake facts plus the local policy that accepted them.
///
/// This function intentionally accepts the transcript hash as input rather than
/// claiming to verify signatures. Production code must call it only after both
/// V2 host/viewer transcript signature suites have been verified successfully.
pub fn derive_authority_activation_receipt(
    host_offer: &CapabilityOfferV1,
    viewer_offer: &CapabilityOfferV1,
    base_v4_context_hash: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    host_identity_fingerprint: [u8; 32],
    policy: &NegotiationPolicyV1,
) -> Result<AuthorityActivationReceiptV1, AuthorityActivationEvidenceError> {
    require_nonzero(base_v4_context_hash)?;
    require_nonzero(handshake_transcript_hash)?;
    require_nonzero(host_identity_fingerprint)?;

    let negotiation = negotiate_capabilities(host_offer, viewer_offer)?;
    require_causal_authority_draft04_evidence(&negotiation)?;
    policy.evaluate(negotiation.selected_context())?;

    let final_v5_context_hash =
        compose_v5_context(&base_v4_context_hash, &negotiation.binding_hash());
    let lineage_id = derive_authority_lineage_id(
        &handshake_transcript_hash,
        &final_v5_context_hash,
        &host_identity_fingerprint,
    );
    let activation_id = derive_authority_activation_id(&lineage_id, &policy.hash());

    Ok(AuthorityActivationReceiptV1 {
        schema_version: AUTHORITY_ACTIVATION_RECEIPT_SCHEMA_VERSION,
        handshake_transcript_hash,
        base_v4_context_hash,
        final_v5_context_hash,
        host_offer_hash: negotiation.host_offer_hash(),
        viewer_offer_hash: negotiation.viewer_offer_hash(),
        selected_context_hash: negotiation.selected_context().hash(),
        negotiation_binding_hash: negotiation.binding_hash(),
        local_policy_hash: policy.hash(),
        host_identity_fingerprint,
        lineage_id,
        activation_id,
    })
}

/// Derive the public cryptographic lineage identifier for one authenticated V2
/// session. Local downgrade policy is intentionally excluded so policy changes
/// do not masquerade as a different handshake/rekey lineage.
pub fn derive_authority_lineage_id(
    handshake_transcript_hash: &[u8; 32],
    final_v5_context_hash: &[u8; 32],
    host_identity_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_LINEAGE_V1_DOMAIN);
    hasher.update(handshake_transcript_hash);
    hasher.update(final_v5_context_hash);
    hasher.update(host_identity_fingerprint);
    hasher.finalize().into()
}

/// Derive the local policy-bound activation identity for one authority lineage.
pub fn derive_authority_activation_id(
    lineage_id: &[u8; 32],
    local_policy_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_ACTIVATION_V1_DOMAIN);
    hasher.update(lineage_id);
    hasher.update(local_policy_hash);
    hasher.finalize().into()
}

fn require_nonzero(value: [u8; 32]) -> Result<(), AuthorityActivationEvidenceError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(AuthorityActivationEvidenceError::ZeroCommitment)
    } else {
        Ok(())
    }
}

/// Failure while deriving or verifying durable authority activation evidence.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityActivationEvidenceError {
    /// Canonical capability negotiation failed.
    #[error(transparent)]
    Negotiation(#[from] NegotiatedContextError),
    /// Exact causal-authority draft-04 was not deterministically selected.
    #[error(transparent)]
    Authority(#[from] AuthorityNegotiationError),
    /// The local minimum/allow-list policy rejected the authenticated selection.
    #[error(transparent)]
    Policy(#[from] NegotiationPolicyError),
    /// A required cryptographic commitment was the all-zero sentinel.
    #[error("authority activation evidence contains an all-zero commitment")]
    ZeroCommitment,
    /// Deserialized receipt has a schema version this implementation does not understand.
    #[error("unsupported authority activation receipt schema version")]
    UnsupportedSchemaVersion,
    /// Re-derived receipt differs from the exported/deserialized receipt.
    #[error("authority activation receipt does not match deterministic re-derivation")]
    ReceiptMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::negotiated_context::{CapabilityOfferEntryV1, NegotiatedCapabilityV1};

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn representative_offers() -> (CapabilityOfferV1, CapabilityOfferV1) {
        let host = CapabilityOfferV1::from_entries([
            entry(
                b"xenia.causal-authority",
                &[b"draft-04", b"draft-03"],
            ),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let viewer = CapabilityOfferV1::from_entries([
            entry(b"xenia.causal-authority", &[b"draft-04"]),
            entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        (host, viewer)
    }

    #[test]
    fn freezes_policy_bound_activation_receipt_vector() {
        let (host, viewer) = representative_offers();
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        let receipt = derive_authority_activation_receipt(
            &host,
            &viewer,
            core::array::from_fn(|index| index as u8),
            [0x11; 32],
            [0x22; 32],
            &policy,
        )
        .unwrap();

        assert_eq!(
            hex(&receipt.final_v5_context_hash),
            "9f59efa7ef0959faf57c2490eb438d5537e1485f4bf4f2841cc0df76a647f584"
        );
        assert_eq!(
            hex(&receipt.lineage_id),
            "cb7a0bc37fb04a286479a9bede740b68cb9c6a86f60257822989c2843028a0da"
        );
        assert_eq!(
            hex(&receipt.activation_id),
            "1ba70773ca4179593c90279e44f407688583b976bd7028d05c3feccfbc6840c3"
        );
        assert_eq!(receipt.canonical_bytes().len(), 391);
        assert_eq!(
            hex(&receipt.receipt_digest()),
            "d1e0abbfcfbb6e65662a3faa38d9bb350696b30d6c454f5a2cf81cebfe3b37e9"
        );
        receipt
            .verify_internal_consistency(&host, &viewer, &policy)
            .unwrap();
    }

    #[test]
    fn local_policy_changes_activation_but_not_lineage() {
        let (host, viewer) = representative_offers();
        let authority = causal_authority_draft04_capability();
        let minimum = NegotiationPolicyV1::minimum_required([authority.clone()]).unwrap();
        let strict = NegotiationPolicyV1::allow_list(
            [authority.clone()],
            [
                authority,
                NegotiatedCapabilityV1::new(
                    b"xenia.operator-rekey".to_vec(),
                    b"v1".to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap();

        let a = derive_authority_activation_receipt(
            &host,
            &viewer,
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            &minimum,
        )
        .unwrap();
        let b = derive_authority_activation_receipt(
            &host,
            &viewer,
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            &strict,
        )
        .unwrap();

        assert_eq!(a.lineage_id, b.lineage_id);
        assert_ne!(a.local_policy_hash, b.local_policy_hash);
        assert_ne!(a.activation_id, b.activation_id);
        assert_ne!(a.receipt_digest(), b.receipt_digest());
    }

    #[test]
    fn downgrade_and_unreviewed_extension_fail_closed() {
        let host = CapabilityOfferV1::from_entries([entry(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-03"],
        )])
        .unwrap();
        let downgraded_viewer = CapabilityOfferV1::from_entries([entry(
            b"xenia.causal-authority",
            &[b"draft-03"],
        )])
        .unwrap();
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        assert!(derive_authority_activation_receipt(
            &host,
            &downgraded_viewer,
            [1; 32],
            [2; 32],
            [3; 32],
            &policy,
        )
        .is_err());

        let (host, viewer) = representative_offers();
        let authority = causal_authority_draft04_capability();
        let strict = NegotiationPolicyV1::allow_list(
            [authority.clone()],
            [authority],
        )
        .unwrap();
        assert!(derive_authority_activation_receipt(
            &host,
            &viewer,
            [1; 32],
            [2; 32],
            [3; 32],
            &strict,
        )
        .is_err());
    }

    #[test]
    fn exported_receipt_mutation_is_detected() {
        let (host, viewer) = representative_offers();
        let policy = NegotiationPolicyV1::minimum_required([
            causal_authority_draft04_capability(),
        ])
        .unwrap();
        let mut receipt = derive_authority_activation_receipt(
            &host,
            &viewer,
            [1; 32],
            [2; 32],
            [3; 32],
            &policy,
        )
        .unwrap();
        receipt.activation_id[0] ^= 0x80;
        assert!(matches!(
            receipt.verify_internal_consistency(&host, &viewer, &policy),
            Err(AuthorityActivationEvidenceError::ReceiptMismatch)
        ));
    }
}
