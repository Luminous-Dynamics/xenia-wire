// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical negotiated-capability context for authenticated handshakes.
//!
//! This module deliberately separates *canonicalization* from *authentication*.
//! [`NegotiatedContextV1`] says what capability set was selected and provides a
//! stable digest for transcript binding. It does **not** prove that either peer
//! advertised, accepted, or authenticated that set. A caller must only treat a
//! context as authoritative after its [`NegotiatedContextV1::hash`] has been
//! bound into and authenticated by the handshake transcript.
//!
//! The distinction is load-bearing: an application-provided `bool` such as
//! `supports_causal_authority`, or an arbitrary caller-provided `[u8; 32]`, is
//! not negotiation evidence.

#![cfg(feature = "handshake")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for canonical negotiated-capability contexts.
pub const NEGOTIATED_CONTEXT_V1_DOMAIN: &[u8] = b"xenia.negotiated-context.v1\0";

/// Stable digest algorithm label for negotiated contexts.
pub const NEGOTIATED_CONTEXT_HASH_ALGORITHM: &str = "sha256";

/// Maximum number of capabilities in one negotiated context.
pub const MAX_NEGOTIATED_CAPABILITIES: usize = 64;

/// Maximum canonical capability-name length.
pub const MAX_CAPABILITY_NAME_BYTES: usize = 128;

/// Maximum canonical capability-version length.
pub const MAX_CAPABILITY_VERSION_BYTES: usize = 32;

/// One canonical negotiated capability.
///
/// Names and versions are bytes rather than Unicode strings so independent
/// implementations cannot disagree about case folding or normalization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NegotiatedCapabilityV1 {
    name: Vec<u8>,
    version: Vec<u8>,
}

impl NegotiatedCapabilityV1 {
    /// Construct and validate one canonical capability identifier.
    pub fn new(
        name: impl Into<Vec<u8>>,
        version: impl Into<Vec<u8>>,
    ) -> Result<Self, NegotiatedContextError> {
        let capability = Self {
            name: name.into(),
            version: version.into(),
        };
        capability.validate()?;
        Ok(capability)
    }

    /// Canonical capability-name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Canonical capability-version bytes.
    pub fn version(&self) -> &[u8] {
        &self.version
    }

    fn validate(&self) -> Result<(), NegotiatedContextError> {
        if self.name.is_empty() {
            return Err(NegotiatedContextError::EmptyCapabilityName);
        }
        if self.name.len() > MAX_CAPABILITY_NAME_BYTES {
            return Err(NegotiatedContextError::CapabilityNameTooLong);
        }
        if self.version.is_empty() {
            return Err(NegotiatedContextError::EmptyCapabilityVersion);
        }
        if self.version.len() > MAX_CAPABILITY_VERSION_BYTES {
            return Err(NegotiatedContextError::CapabilityVersionTooLong);
        }
        Ok(())
    }
}

/// Canonical selected capability set plus its transcript-binding digest.
///
/// Capabilities are sorted lexicographically by exact `(name, version)` bytes
/// before hashing. This makes the selected-set digest independent of local
/// advertisement order while still allowing the surrounding handshake
/// transcript to bind the exact advertisements separately. A selected context
/// may contain at most one version for any exact capability name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedContextV1 {
    capabilities: Vec<NegotiatedCapabilityV1>,
    hash: [u8; 32],
}

impl NegotiatedContextV1 {
    /// Canonicalize and hash a selected capability set.
    ///
    /// Every exact capability name maps to exactly one selected version. Exact
    /// duplicates and multiple versions for the same name therefore fail closed
    /// rather than being silently deduplicated or left ambiguous.
    pub fn from_capabilities<I>(capabilities: I) -> Result<Self, NegotiatedContextError>
    where
        I: IntoIterator<Item = NegotiatedCapabilityV1>,
    {
        let mut capabilities: Vec<_> = capabilities.into_iter().collect();
        if capabilities.len() > MAX_NEGOTIATED_CAPABILITIES {
            return Err(NegotiatedContextError::TooManyCapabilities);
        }
        for capability in &capabilities {
            capability.validate()?;
        }

        capabilities.sort();
        if capabilities
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(NegotiatedContextError::DuplicateCapabilityName);
        }

        let hash = hash_capabilities(&capabilities);
        Ok(Self { capabilities, hash })
    }

    /// Canonical ordered selected capabilities.
    pub fn capabilities(&self) -> &[NegotiatedCapabilityV1] {
        &self.capabilities
    }

    /// SHA-256 digest to bind into the authenticated handshake transcript.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Whether this exact name/version pair is present in the selected set.
    pub fn contains(&self, name: &[u8], version: &[u8]) -> bool {
        self.capabilities
            .binary_search_by(|capability| {
                capability
                    .name()
                    .cmp(name)
                    .then_with(|| capability.version().cmp(version))
            })
            .is_ok()
    }

    /// Compare an authenticated handshake's observed negotiated-context hash
    /// with this expected canonical context.
    ///
    /// This function only compares digests. The caller is responsible for
    /// ensuring `observed` came from a successfully authenticated transcript.
    pub fn require_observed_hash(
        &self,
        observed: Option<[u8; 32]>,
    ) -> Result<(), NegotiatedContextError> {
        let observed = observed.ok_or(NegotiatedContextError::MissingNegotiatedContext)?;
        if observed != self.hash {
            return Err(NegotiatedContextError::NegotiatedContextMismatch);
        }
        Ok(())
    }
}

fn hash_capabilities(capabilities: &[NegotiatedCapabilityV1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATED_CONTEXT_V1_DOMAIN);
    hasher.update(
        u32::try_from(capabilities.len())
            .expect("capability count is bounded below u32::MAX")
            .to_be_bytes(),
    );

    for capability in capabilities {
        hash_len_prefixed(&mut hasher, capability.name());
        hash_len_prefixed(&mut hasher, capability.version());
    }

    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("capability component is bounded below u16::MAX");
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

/// Negotiated-context construction or verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegotiatedContextError {
    /// More capabilities were supplied than the protocol permits.
    #[error("too many negotiated capabilities")]
    TooManyCapabilities,
    /// Capability name is empty.
    #[error("capability name must not be empty")]
    EmptyCapabilityName,
    /// Capability name exceeds the protocol bound.
    #[error("capability name exceeds negotiated-context bound")]
    CapabilityNameTooLong,
    /// Capability version is empty.
    #[error("capability version must not be empty")]
    EmptyCapabilityVersion,
    /// Capability version exceeds the protocol bound.
    #[error("capability version exceeds negotiated-context bound")]
    CapabilityVersionTooLong,
    /// More than one selected entry uses the same exact capability name.
    #[error("negotiated capability name has more than one selected version")]
    DuplicateCapabilityName,
    /// A strict profile was required but the authenticated handshake carried no
    /// negotiated-context hash.
    #[error("authenticated handshake did not carry a negotiated context")]
    MissingNegotiatedContext,
    /// The authenticated handshake context differs from the expected canonical
    /// selected capability set.
    #[error("authenticated negotiated context does not match expected capability set")]
    NegotiatedContextMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &[u8], version: &[u8]) -> NegotiatedCapabilityV1 {
        NegotiatedCapabilityV1::new(name.to_vec(), version.to_vec()).unwrap()
    }

    #[test]
    fn selected_set_hash_is_order_independent() {
        let a = NegotiatedContextV1::from_capabilities([
            cap(b"xenia.causal-authority", b"draft-04"),
            cap(b"xenia.operator-rekey", b"v1"),
        ])
        .unwrap();
        let b = NegotiatedContextV1::from_capabilities([
            cap(b"xenia.operator-rekey", b"v1"),
            cap(b"xenia.causal-authority", b"draft-04"),
        ])
        .unwrap();

        assert_eq!(a, b);
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn authority_only_context_has_frozen_sha256_vector() {
        let context = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-04",
        )])
        .unwrap();
        assert_eq!(
            context.hash(),
            [
                0xff, 0xd0, 0xc4, 0xad, 0x0b, 0x13, 0x3e, 0x8a, 0xae, 0x58, 0xb0, 0xa7, 0x9b,
                0x51, 0x0f, 0xa9, 0x0f, 0x5e, 0xbf, 0xf9, 0x77, 0x51, 0xb5, 0xfc, 0x2b, 0x55,
                0xa7, 0xff, 0x79, 0x6c, 0x2a, 0x85,
            ]
        );
    }

    #[test]
    fn version_change_changes_context_hash() {
        let draft04 = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-04",
        )])
        .unwrap();
        let draft05 = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-05",
        )])
        .unwrap();

        assert_ne!(draft04.hash(), draft05.hash());
    }

    #[test]
    fn duplicate_or_multi_version_capability_name_fails_closed() {
        let capability = cap(b"xenia.causal-authority", b"draft-04");
        let duplicate = NegotiatedContextV1::from_capabilities([
            capability.clone(),
            capability,
        ]);
        assert_eq!(
            duplicate.unwrap_err(),
            NegotiatedContextError::DuplicateCapabilityName
        );

        let multi_version = NegotiatedContextV1::from_capabilities([
            cap(b"xenia.causal-authority", b"draft-03"),
            cap(b"xenia.causal-authority", b"draft-04"),
        ]);
        assert_eq!(
            multi_version.unwrap_err(),
            NegotiatedContextError::DuplicateCapabilityName
        );
    }

    #[test]
    fn missing_or_wrong_observed_context_fails_closed() {
        let context = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-04",
        )])
        .unwrap();

        assert_eq!(
            context.require_observed_hash(None).unwrap_err(),
            NegotiatedContextError::MissingNegotiatedContext
        );
        assert_eq!(
            context.require_observed_hash(Some([0xA5; 32])).unwrap_err(),
            NegotiatedContextError::NegotiatedContextMismatch
        );
        assert!(context.require_observed_hash(Some(context.hash())).is_ok());
    }

    #[test]
    fn exact_byte_identity_is_load_bearing() {
        let context = NegotiatedContextV1::from_capabilities([cap(
            b"xenia.causal-authority",
            b"draft-04",
        )])
        .unwrap();

        assert!(context.contains(b"xenia.causal-authority", b"draft-04"));
        assert!(!context.contains(b"XENIA.CAUSAL-AUTHORITY", b"draft-04"));
        assert!(!context.contains(b"xenia.causal-authority", b"DRAFT-04"));
    }

    #[test]
    fn identifier_bounds_are_enforced() {
        assert_eq!(
            NegotiatedCapabilityV1::new(Vec::<u8>::new(), b"v1".to_vec()).unwrap_err(),
            NegotiatedContextError::EmptyCapabilityName
        );
        assert_eq!(
            NegotiatedCapabilityV1::new(
                vec![b'n'; MAX_CAPABILITY_NAME_BYTES + 1],
                b"v1".to_vec()
            )
            .unwrap_err(),
            NegotiatedContextError::CapabilityNameTooLong
        );
        assert_eq!(
            NegotiatedCapabilityV1::new(b"xenia.test".to_vec(), Vec::<u8>::new()).unwrap_err(),
            NegotiatedContextError::EmptyCapabilityVersion
        );
        assert_eq!(
            NegotiatedCapabilityV1::new(
                b"xenia.test".to_vec(),
                vec![b'v'; MAX_CAPABILITY_VERSION_BYTES + 1]
            )
            .unwrap_err(),
            NegotiatedContextError::CapabilityVersionTooLong
        );
    }
}
