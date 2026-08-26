// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Causal-authority capability profile for authenticated handshake negotiation.
//!
//! This module is available only when both `causal-authority` and `handshake`
//! are enabled. It defines the exact capability identifier that a strict
//! draft-04 deployment must include in its authenticated negotiated context.
//!
//! The helpers here intentionally do not accept a boolean such as
//! `supports_causal_authority`. Authority availability is represented by exact
//! canonical bytes inside [`crate::negotiated_context::NegotiatedContextV1`].

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use crate::negotiated_context::{
    NegotiatedCapabilityV1, NegotiatedContextError, NegotiatedContextV1,
};

/// Canonical capability name for request-bound causal authority.
pub const CAUSAL_AUTHORITY_CAPABILITY_NAME: &[u8] = b"xenia.causal-authority";

/// Canonical capability version for the draft-04 candidate protocol.
pub const CAUSAL_AUTHORITY_CAPABILITY_VERSION: &[u8] = b"draft-04";

/// Construct the exact draft-04 causal-authority capability identifier.
pub fn causal_authority_draft04_capability() -> NegotiatedCapabilityV1 {
    NegotiatedCapabilityV1::new(
        CAUSAL_AUTHORITY_CAPABILITY_NAME.to_vec(),
        CAUSAL_AUTHORITY_CAPABILITY_VERSION.to_vec(),
    )
    .expect("built-in causal-authority capability satisfies negotiated-context bounds")
}

/// Require that a canonical selected-capability context contains exact
/// causal-authority draft-04 support.
///
/// This proves only membership in the supplied canonical context. The context's
/// hash must additionally be authenticated by the handshake transcript before
/// an application treats the capability as negotiated.
pub fn require_causal_authority_draft04(
    context: &NegotiatedContextV1,
) -> Result<(), AuthorityNegotiationError> {
    if context.contains(
        CAUSAL_AUTHORITY_CAPABILITY_NAME,
        CAUSAL_AUTHORITY_CAPABILITY_VERSION,
    ) {
        Ok(())
    } else {
        Err(AuthorityNegotiationError::CausalAuthorityNotNegotiated)
    }
}

/// Build a canonical selected context and require exact causal-authority
/// draft-04 membership.
///
/// Additional capabilities are preserved and therefore affect the context hash;
/// this prevents a caller from checking only a special-case authority bit while
/// ignoring the rest of the negotiated protocol surface.
pub fn causal_authority_context<I>(
    capabilities: I,
) -> Result<NegotiatedContextV1, AuthorityNegotiationError>
where
    I: IntoIterator<Item = NegotiatedCapabilityV1>,
{
    let context = NegotiatedContextV1::from_capabilities(capabilities)?;
    require_causal_authority_draft04(&context)?;
    Ok(context)
}

/// Causal-authority negotiation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityNegotiationError {
    /// Canonical context construction or digest verification failed.
    #[error(transparent)]
    Context(#[from] NegotiatedContextError),
    /// The selected capability set does not contain exact draft-04 causal
    /// authority support.
    #[error("causal-authority draft-04 was not negotiated")]
    CausalAuthorityNotNegotiated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_draft04_capability_is_required() {
        let context = NegotiatedContextV1::from_capabilities([
            NegotiatedCapabilityV1::new(b"xenia.causal-authority".to_vec(), b"draft-03".to_vec())
                .unwrap(),
        ])
        .unwrap();

        assert_eq!(
            require_causal_authority_draft04(&context).unwrap_err(),
            AuthorityNegotiationError::CausalAuthorityNotNegotiated
        );
    }

    #[test]
    fn additional_selected_capabilities_are_bound_into_hash() {
        let authority_only = causal_authority_context([causal_authority_draft04_capability()])
            .unwrap();
        let authority_plus_rekey = causal_authority_context([
            causal_authority_draft04_capability(),
            NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec())
                .unwrap(),
        ])
        .unwrap();

        assert_ne!(authority_only.hash(), authority_plus_rekey.hash());
        assert!(require_causal_authority_draft04(&authority_plus_rekey).is_ok());
    }
}
