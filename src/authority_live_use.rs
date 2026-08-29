// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Session-borrowed online authority verification.
//!
//! Durable [`crate::authority::VerifiedExternalActionAuthority`] values are useful
//! evidence, but evidence should not accidentally become a detached live
//! capability. This module adds the recommended online-use shape for negotiated
//! authority sessions: verification returns a non-serializable token borrowing
//! the [`crate::authority_session::NegotiatedAuthoritySession`] that established
//! the authority lineage.
//!
//! While the token exists, safe Rust cannot mutably borrow the authority session
//! for rekey or consume it back into a raw [`crate::Session`]. The verified action
//! therefore remains tied to the same activation and key epoch for the duration
//! of the online-use decision. Durable single-use reservation/consumption remains
//! an application/execution-layer responsibility keyed by `authority_id`.
//!
//! The borrow boundary is compiler-enforced:
//!
//! ```compile_fail
//! use xenia_wire::authority::CausalAuthorityResponse;
//! use xenia_wire::authority_session::NegotiatedAuthoritySession;
//! use xenia_wire::consent::{ConsentRequest, PUBLIC_KEY_LEN};
//!
//! fn cannot_mutate_while_live_use_exists(
//!     session: &mut NegotiatedAuthoritySession,
//!     request: &ConsentRequest,
//!     response: &CausalAuthorityResponse,
//!     requester: &[u8; PUBLIC_KEY_LEN],
//!     responder: &[u8; PUBLIC_KEY_LEN],
//! ) {
//!     let live = session
//!         .verify_session_bound_authority(
//!             request,
//!             response,
//!             &[],
//!             requester,
//!             responder,
//!             1,
//!         )
//!         .unwrap();
//!     session.tick(); // rejected: `live` still immutably borrows `session`
//!     drop(live);
//! }
//! ```

#![cfg(all(feature = "causal-authority", feature = "handshake"))]

use crate::authority::{CausalAuthorityResponse, VerifiedExternalActionAuthority};
use crate::authority_session::{AuthoritySessionError, NegotiatedAuthoritySession};
use crate::consent::{ConsentRequest, ConsentRevocation, PUBLIC_KEY_LEN};

/// Fresh online authority verification tied to one borrowed authority session.
///
/// This type intentionally implements neither `Clone` nor serialization and has
/// no public constructor. It cannot outlive the borrowed
/// [`NegotiatedAuthoritySession`]. Consumers that need durable audit evidence may
/// read [`Self::evidence`], but must not reinterpret a copied evidence record as
/// proof that the original live session or key epoch still exists.
pub struct SessionBoundAuthorityUse<'session> {
    evidence: VerifiedExternalActionAuthority,
    lineage_id: [u8; 32],
    activation_id: [u8; 32],
    key_epoch: u64,
    _session: &'session NegotiatedAuthoritySession,
}

impl<'session> SessionBoundAuthorityUse<'session> {
    /// Verified signed authority evidence for inspection and execution binding.
    pub fn evidence(&self) -> &VerifiedExternalActionAuthority {
        &self.evidence
    }

    /// Stable authority instance id used for durable single-use reservation.
    pub fn authority_id(&self) -> &[u8; 32] {
        &self.evidence.authority_id
    }

    /// Authenticated session-lineage id at verification time.
    pub fn lineage_id(&self) -> &[u8; 32] {
        &self.lineage_id
    }

    /// Local policy-bound activation id at verification time.
    pub fn activation_id(&self) -> &[u8; 32] {
        &self.activation_id
    }

    /// Verified Xenia key epoch at verification time.
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

impl NegotiatedAuthoritySession {
    /// Verify one exact action and return a token borrowing this live authority
    /// session.
    ///
    /// The returned borrow prevents `apply_verified_rekey(&mut self)` and
    /// `into_raw_session(self)` from being called until the token is dropped.
    /// This closes the gap where a detached verified object could otherwise be
    /// treated as if it still described the current live session after a rekey or
    /// authority teardown.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_session_bound_authority<'session>(
        &'session self,
        request: &ConsentRequest,
        response: &CausalAuthorityResponse,
        revocations: &[ConsentRevocation],
        expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
        expected_responder_pubkey: &[u8; PUBLIC_KEY_LEN],
        now_ms: u64,
    ) -> Result<SessionBoundAuthorityUse<'session>, AuthoritySessionError> {
        let evidence = self.verify_approved_external_action_authority(
            request,
            response,
            revocations,
            expected_requester_pubkey,
            expected_responder_pubkey,
            now_ms,
        )?;
        Ok(SessionBoundAuthorityUse {
            evidence,
            lineage_id: self.lineage().lineage_id,
            activation_id: self.lineage().activation_id,
            key_epoch: self.lineage().key_epoch,
            _session: self,
        })
    }
}
