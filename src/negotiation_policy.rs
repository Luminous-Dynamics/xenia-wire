// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical local policy over an authenticated negotiated-capability context.
//!
//! Policy is deliberately distinct from negotiation. The handshake authenticates
//! peer offers, deterministic selection, and the resulting context; local policy
//! decides whether that authenticated result is acceptable. A policy hash is
//! suitable for audit/receipt binding, but is not itself peer-negotiation evidence.

#![cfg(feature = "handshake")]

use sha2::{Digest, Sha256};

use crate::negotiated_context::{
    MAX_NEGOTIATED_CAPABILITIES, NegotiatedCapabilityV1, NegotiatedContextV1,
};

/// Domain separator for canonical local negotiation policy hashes.
pub const NEGOTIATION_POLICY_V1_DOMAIN: &[u8] = b"xenia.negotiation-policy.v1\0";

/// Maximum number of exact entries in either local policy list.
pub const MAX_POLICY_CAPABILITIES: usize = MAX_NEGOTIATED_CAPABILITIES;

/// How strictly selected capabilities are constrained beyond the required set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyModeV1 {
    /// Every required exact capability must be selected; authenticated extras are allowed.
    Minimum = 0,
    /// Required exact capabilities must be selected and every selected exact
    /// capability must appear in the local allow-list.
    AllowList = 1,
}

/// Canonical local acceptance policy for one authenticated selected context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationPolicyV1 {
    mode: PolicyModeV1,
    required: Vec<NegotiatedCapabilityV1>,
    allowed: Vec<NegotiatedCapabilityV1>,
    hash: [u8; 32],
}

impl NegotiationPolicyV1 {
    /// Require exact capabilities while permitting additional authenticated capabilities.
    pub fn minimum_required<I>(required: I) -> Result<Self, NegotiationPolicyError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        let required = canonical_required(required)?;
        let allowed = Vec::new();
        let hash = hash_policy(PolicyModeV1::Minimum, &required, &allowed);
        Ok(Self {
            mode: PolicyModeV1::Minimum,
            required,
            allowed,
            hash,
        })
    }

    /// Require exact capabilities and reject any selected capability outside an
    /// explicit exact allow-list.
    ///
    /// The allow-list may contain multiple versions for one name because the
    /// negotiated selected context still chooses exactly one. Required entries
    /// may not contain multiple versions for one name because such a policy is
    /// unsatisfiable by construction.
    pub fn allow_list<I, J>(required: I, allowed: J) -> Result<Self, NegotiationPolicyError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
        J: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        let required = canonical_required(required)?;
        let allowed = canonical_allowed(allowed)?;
        if required
            .iter()
            .any(|requirement| allowed.binary_search(requirement).is_err())
        {
            return Err(NegotiationPolicyError::RequiredCapabilityNotAllowed);
        }
        let hash = hash_policy(PolicyModeV1::AllowList, &required, &allowed);
        Ok(Self {
            mode: PolicyModeV1::AllowList,
            required,
            allowed,
            hash,
        })
    }

    /// Policy mode.
    pub fn mode(&self) -> PolicyModeV1 {
        self.mode
    }

    /// Canonical exact capability requirements.
    pub fn required(&self) -> &[NegotiatedCapabilityV1] {
        &self.required
    }

    /// Canonical exact allow-list; empty in minimum mode.
    pub fn allowed(&self) -> &[NegotiatedCapabilityV1] {
        &self.allowed
    }

    /// SHA-256 identity of the canonical local policy.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Evaluate an authenticated deterministic selected context.
    ///
    /// The type system cannot prove the caller obtained `selected` from a
    /// completed handshake. Consequential callers must only invoke this after
    /// the negotiation binding has been authenticated by the handshake transcript.
    pub fn evaluate(&self, selected: &NegotiatedContextV1) -> Result<(), NegotiationPolicyError> {
        if self
            .required
            .iter()
            .any(|required| !selected.contains(required.name(), required.version()))
        {
            return Err(NegotiationPolicyError::RequiredCapabilityMissing);
        }
        if self.mode == PolicyModeV1::AllowList
            && selected
                .capabilities()
                .iter()
                .any(|capability| self.allowed.binary_search(capability).is_err())
        {
            return Err(NegotiationPolicyError::SelectedCapabilityNotAllowed);
        }
        Ok(())
    }
}

fn canonical_required<I>(required: I) -> Result<Vec<NegotiatedCapabilityV1>, NegotiationPolicyError>
where
    I: IntoIterator<Item = NegotiatedCapabilityV1>,
{
    let mut required: Vec<_> = required.into_iter().collect();
    if required.len() > MAX_POLICY_CAPABILITIES {
        return Err(NegotiationPolicyError::TooManyPolicyCapabilities);
    }
    required.sort();
    if required
        .windows(2)
        .any(|pair| pair[0].name() == pair[1].name())
    {
        return Err(NegotiationPolicyError::DuplicateRequiredCapabilityName);
    }
    Ok(required)
}

fn canonical_allowed<I>(allowed: I) -> Result<Vec<NegotiatedCapabilityV1>, NegotiationPolicyError>
where
    I: IntoIterator<Item = NegotiatedCapabilityV1>,
{
    let mut allowed: Vec<_> = allowed.into_iter().collect();
    if allowed.len() > MAX_POLICY_CAPABILITIES {
        return Err(NegotiationPolicyError::TooManyPolicyCapabilities);
    }
    allowed.sort();
    if allowed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(NegotiationPolicyError::DuplicateAllowedCapability);
    }
    Ok(allowed)
}

fn hash_policy(
    mode: PolicyModeV1,
    required: &[NegotiatedCapabilityV1],
    allowed: &[NegotiatedCapabilityV1],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_POLICY_V1_DOMAIN);
    hasher.update([mode as u8]);
    hash_capability_list(&mut hasher, required);
    hash_capability_list(&mut hasher, allowed);
    hasher.finalize().into()
}

fn hash_capability_list(hasher: &mut Sha256, capabilities: &[NegotiatedCapabilityV1]) {
    hasher.update(
        u32::try_from(capabilities.len())
            .expect("policy capability count is bounded below u32::MAX")
            .to_be_bytes(),
    );
    for capability in capabilities {
        hash_len_prefixed(hasher, capability.name());
        hash_len_prefixed(hasher, capability.version());
    }
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("negotiated identifiers are u16-bounded");
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

/// Failure while constructing or enforcing local negotiated-capability policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegotiationPolicyError {
    /// A policy list exceeds the selected-capability protocol bound.
    #[error("too many capabilities in negotiation policy")]
    TooManyPolicyCapabilities,
    /// Required policy asks for more than one version of a capability name.
    #[error("required policy contains more than one version for a capability name")]
    DuplicateRequiredCapabilityName,
    /// Allow-list repeats one exact capability/version pair.
    #[error("allow-list repeats an exact capability/version pair")]
    DuplicateAllowedCapability,
    /// Required exact capability is absent from the allow-list.
    #[error("required capability is not present in allow-list")]
    RequiredCapabilityNotAllowed,
    /// Authenticated selected context omitted an exact local requirement.
    #[error("authenticated negotiation is missing a required exact capability")]
    RequiredCapabilityMissing,
    /// Authenticated selected context contains an unlisted exact capability.
    #[error("authenticated negotiation selected a capability outside the local allow-list")]
    SelectedCapabilityNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
        NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
    }

    fn selected(
        capabilities: impl IntoIterator<Item = NegotiatedCapabilityV1>,
    ) -> NegotiatedContextV1 {
        NegotiatedContextV1::from_capabilities(capabilities).unwrap()
    }

    #[test]
    fn minimum_policy_rejects_downgrade_but_allows_authenticated_extras() {
        let policy =
            NegotiationPolicyV1::minimum_required([cap(b"xenia.causal-authority", b"draft-04")])
                .unwrap();
        assert!(
            policy
                .evaluate(&selected([
                    cap(b"xenia.causal-authority", b"draft-04"),
                    cap(b"xenia.operator-rekey", b"v1"),
                ]))
                .is_ok()
        );
        assert_eq!(
            policy
                .evaluate(&selected([cap(b"xenia.causal-authority", b"draft-03")]))
                .unwrap_err(),
            NegotiationPolicyError::RequiredCapabilityMissing
        );
    }

    #[test]
    fn allow_list_rejects_unreviewed_selected_extensions() {
        let authority = cap(b"xenia.causal-authority", b"draft-04");
        let rekey = cap(b"xenia.operator-rekey", b"v1");
        let policy = NegotiationPolicyV1::allow_list(
            [authority.clone()],
            [authority.clone(), rekey.clone()],
        )
        .unwrap();
        assert!(
            policy
                .evaluate(&selected([authority.clone(), rekey]))
                .is_ok()
        );
        assert_eq!(
            policy
                .evaluate(&selected([
                    authority,
                    cap(b"xenia.future-extension", b"v1"),
                ]))
                .unwrap_err(),
            NegotiationPolicyError::SelectedCapabilityNotAllowed
        );
    }

    #[test]
    fn unsatisfiable_required_policy_and_incomplete_allow_list_fail_closed() {
        assert_eq!(
            NegotiationPolicyV1::minimum_required([
                cap(b"xenia.causal-authority", b"draft-03"),
                cap(b"xenia.causal-authority", b"draft-04"),
            ])
            .unwrap_err(),
            NegotiationPolicyError::DuplicateRequiredCapabilityName
        );
        assert_eq!(
            NegotiationPolicyV1::allow_list(
                [cap(b"xenia.causal-authority", b"draft-04")],
                [cap(b"xenia.causal-authority", b"draft-03")],
            )
            .unwrap_err(),
            NegotiationPolicyError::RequiredCapabilityNotAllowed
        );
    }

    #[test]
    fn policy_hashes_match_independent_native_and_node_vectors() {
        let authority = cap(b"xenia.causal-authority", b"draft-04");
        let minimum = NegotiationPolicyV1::minimum_required([authority.clone()]).unwrap();
        assert_eq!(
            minimum.hash(),
            [
                0x64, 0x56, 0xc4, 0x0a, 0xf9, 0xe1, 0x04, 0xb8, 0x2b, 0xe0, 0xb0, 0xfa, 0xf5, 0x01,
                0xc4, 0x04, 0xc0, 0x57, 0xd7, 0xb5, 0x59, 0x28, 0xd3, 0x39, 0x72, 0x0a, 0x9c, 0x20,
                0x8f, 0x6e, 0xef, 0x0f,
            ]
        );
        let allow_list = NegotiationPolicyV1::allow_list(
            [authority.clone()],
            [authority, cap(b"xenia.operator-rekey", b"v1")],
        )
        .unwrap();
        assert_eq!(
            allow_list.hash(),
            [
                0xed, 0x37, 0x98, 0x3b, 0x2b, 0x76, 0xcb, 0xc7, 0x68, 0x9d, 0x80, 0xef, 0x2f, 0x00,
                0x8b, 0xda, 0xf4, 0x69, 0x48, 0x3b, 0xbc, 0x2a, 0xa1, 0xca, 0xae, 0xd2, 0x35, 0x29,
                0x92, 0xb7, 0xfc, 0xa4,
            ]
        );
    }
}
