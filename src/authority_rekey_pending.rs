// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Post-commit receiver-rekey typestate for the Ack delivery ambiguity window.
//!
//! This module is deliberately additive prototype input for ARR-011. The
//! existing receiver transaction in [`crate::authority_session`] performs the
//! cryptographic/replay/lineage transition. This layer changes ownership and
//! continuation authority: once that transaction commits, the active authority
//! session is moved into [`AuthorityRekeyAckDeliveryPending`] and cannot be used
//! independently while exact Ack delivery is unresolved.
//!
//! The compiler-visible boundary is the important property. Once the consuming
//! transition succeeds, the original authority value has moved:
//!
//! ```compile_fail
//! use xenia_wire::authority_session::NegotiatedAuthoritySession;
//!
//! fn cannot_use_active_authority_while_ack_is_pending(
//!     mut session: NegotiatedAuthoritySession,
//!     sealed_proposal: &[u8],
//! ) {
//!     let pending = session
//!         .accept_operator_rekey_proposal_pending(sealed_proposal)
//!         .unwrap();
//!     session.tick(); // rejected: `session` moved into `pending`
//!     drop(pending);
//! }
//! ```
//!
//! The pending state intentionally has no unrestricted raw-session escape hatch:
//!
//! ```compile_fail
//! use xenia_wire::authority_rekey_pending::AuthorityRekeyAckDeliveryPending;
//!
//! fn cannot_bypass_delivery_barrier(pending: AuthorityRekeyAckDeliveryPending) {
//!     let _raw = pending.into_raw_session();
//! }
//! ```
//!
//! Nor can ordinary application code extract the Ack or declare success directly.
//! The exact Ack capability is handed only to the one caller-supplied transport
//! continuation invoked by [`AuthorityRekeyAckDeliveryPending::resolve_with`]:
//!
//! ```compile_fail
//! use xenia_wire::authority_rekey_pending::AuthorityRekeyAckDeliveryPending;
//!
//! fn cannot_extract_or_forge_delivery_success(pending: AuthorityRekeyAckDeliveryPending) {
//!     let _ack = pending.pending_ack();
//!     let _authority = pending.delivery_succeeded();
//! }
//! ```
//!
//! This still cannot prove remote receipt or make a network transport
//! transactional. A transport implementation can itself misbehave. The narrower
//! claim is local: safe application code has one reactivation path, and that path
//! invokes exactly one `FnOnce` transport continuation with the exact non-`Clone`
//! presealed Ack capability. `Ok(())` reactivates the committed session; any
//! returned error destroys local authority and yields audit evidence only.

#![cfg(all(
    feature = "causal-authority",
    feature = "handshake",
    feature = "operator-rekey"
))]

use core::fmt;
use core::future::Future;

use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_transition_evidence::AuthorityRekeyTransitionEvidenceV1;
use crate::authority_session::{
    AuthorityOperatorRekeyAcceptance, AuthorityOperatorRekeyError, NegotiatedAuthoritySession,
    PendingAuthorityOperatorRekeyAck,
};

/// Pre-commit receiver-rekey rejection that returns ownership of the still-live
/// authority session together with the rejection reason.
///
/// Authentication may already have consumed the offending envelope's live replay
/// slot before a semantic rejection occurs. Returning the session is therefore
/// **not** replay rollback; it only preserves the current key/lineage authority
/// object when the receiver transaction did not cross its commit boundary.
///
/// The session is boxed so this error carrier remains compact under strict
/// Clippy `result_large_err` qualification. Boxing changes representation only;
/// ownership still returns exclusively through [`Self::into_parts`].
#[must_use = "a rejected receiver rekey attempt still owns the live authority session"]
pub struct AuthorityRekeyRejected {
    authority: Box<NegotiatedAuthoritySession>,
    error: AuthorityOperatorRekeyError,
}

impl AuthorityRekeyRejected {
    /// Rejection reason without releasing ownership of the live authority session.
    pub fn error(&self) -> &AuthorityOperatorRekeyError {
        &self.error
    }

    /// Recover the still-live authority session and the rejection reason.
    ///
    /// Any authenticated replay state consumed before semantic rejection remains
    /// consumed inside the returned session.
    pub fn into_parts(self) -> (NegotiatedAuthoritySession, AuthorityOperatorRekeyError) {
        (*self.authority, self.error)
    }
}

impl fmt::Debug for AuthorityRekeyRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyRejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Failed or ambiguous local Ack handoff after the receiver rekey was already
/// committed.
///
/// No active authority session and no Ack capability are retained in this value.
/// The transport error and both durable evidence records are boxed so the
/// `Result` error representation remains compact under strict Clippy even if the
/// evidence schemas grow. Boxing changes ownership representation only: all
/// values are recovered by [`Self::into_parts`]. Recovery requires teardown plus
/// a fresh authenticated session/authority activation.
#[must_use = "ambiguous Ack delivery terminates local authority; preserve or record its evidence"]
pub struct AuthorityRekeyAckDeliveryAmbiguous<E> {
    transport_error: Box<E>,
    transition: Box<AuthorityRekeyTransitionEvidenceV1>,
    lineage: Box<AuthorityLineageEpochEvidenceV1>,
}

impl<E> AuthorityRekeyAckDeliveryAmbiguous<E> {
    /// Transport-owned error reported by the single Ack continuation.
    pub fn transport_error(&self) -> &E {
        &self.transport_error
    }

    /// Durable evidence for the receiver transition that had already committed.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        &self.transition
    }

    /// Durable committed lineage position whose connection generation is now dead.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        &self.lineage
    }

    /// Consume the terminal ambiguity record into transport error plus durable evidence.
    pub fn into_parts(
        self,
    ) -> (
        E,
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        (*self.transport_error, *self.transition, *self.lineage)
    }
}

impl<E: fmt::Debug> fmt::Debug for AuthorityRekeyAckDeliveryAmbiguous<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyAckDeliveryAmbiguous")
            .field("transport_error", &self.transport_error)
            .field("transition", &self.transition)
            .field("lineage", &self.lineage)
            .finish()
    }
}

/// Authority session after the receiver rekey transaction has committed but
/// before the exact presealed Ack delivery outcome is known.
///
/// The active [`NegotiatedAuthoritySession`] is private and owned by this value.
/// Safe callers cannot independently verify/use authority, mutate the session,
/// escape to a raw session, extract the Ack capability, or manually declare Ack
/// success while the ambiguity window is open.
#[must_use = "committed receiver rekey must resolve Ack delivery or terminate the connection generation"]
pub struct AuthorityRekeyAckDeliveryPending {
    authority: NegotiatedAuthoritySession,
    acceptance: AuthorityOperatorRekeyAcceptance,
}

impl AuthorityRekeyAckDeliveryPending {
    /// Durable public evidence for the committed authority rekey transition.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        self.acceptance.transition()
    }

    /// Durable authority-lineage position after the committed transition.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        self.acceptance.lineage()
    }

    /// Resolve the local Ack-delivery barrier through exactly one transport
    /// continuation.
    ///
    /// This method consumes the entire pending authority typestate, extracts the
    /// exact non-`Clone` presealed sequence-zero Ack capability, and invokes
    /// `send_once` exactly once. The continuation receives ownership of that Ack;
    /// application code never receives it through another pending-state API.
    ///
    /// - `Ok(())` returns the active committed new-epoch authority session and
    ///   durable transition/lineage evidence.
    /// - `Err(error)` drops the committed authority session and returns only the
    ///   transport error plus durable evidence. The Ack capability has already
    ///   moved into the one continuation and cannot be recovered for retry.
    ///
    /// A malicious or incorrect transport continuation can still lie by returning
    /// `Ok(())` without actually handing bytes to a carrier, or can copy bytes
    /// internally. This API deliberately narrows that behavior to the transport
    /// implementation TCB; it does not claim to prove remote receipt.
    pub async fn resolve_with<F, Fut, E>(
        self,
        send_once: F,
    ) -> Result<
        (
            NegotiatedAuthoritySession,
            AuthorityRekeyTransitionEvidenceV1,
            AuthorityLineageEpochEvidenceV1,
        ),
        AuthorityRekeyAckDeliveryAmbiguous<E>,
    >
    where
        F: FnOnce(PendingAuthorityOperatorRekeyAck) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let Self {
            authority,
            acceptance,
        } = self;
        let (pending_ack, transition, lineage) = acceptance.into_parts();

        match send_once(pending_ack).await {
            Ok(()) => Ok((authority, transition, lineage)),
            Err(transport_error) => {
                drop(authority);
                Err(AuthorityRekeyAckDeliveryAmbiguous {
                    transport_error: Box::new(transport_error),
                    transition: Box::new(transition),
                    lineage: Box::new(lineage),
                })
            }
        }
    }

    /// Terminate the local authority generation without attempting Ack delivery,
    /// while retaining only durable audit evidence.
    ///
    /// This is intended for an already-dead carrier or explicit local teardown.
    /// The owned active authority session and pending Ack capability are consumed
    /// and dropped. No API returns either one from this path.
    pub fn into_ambiguous_evidence(
        self,
    ) -> (
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        let Self {
            authority,
            acceptance,
        } = self;
        drop(authority);
        let (_pending_ack, transition, lineage) = acceptance.into_parts();
        (transition, lineage)
    }
}

impl fmt::Debug for AuthorityRekeyAckDeliveryPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyAckDeliveryPending")
            .field("transition", self.transition())
            .field("lineage", self.lineage())
            .finish_non_exhaustive()
    }
}

impl NegotiatedAuthoritySession {
    /// Consume this active authority session through one receiver-side operator
    /// rekey attempt and expose an explicit post-commit Ack-delivery typestate.
    ///
    /// - Rejection before the existing receiver commit boundary returns
    ///   [`AuthorityRekeyRejected`], which owns the still-live session plus the
    ///   rejection reason. Authenticated semantic rejection remains
    ///   replay-consumed exactly as in the underlying receiver transaction.
    /// - Success returns [`AuthorityRekeyAckDeliveryPending`]. The committed
    ///   authority session is no longer independently available until the
    ///   transport owner resolves Ack delivery through `resolve_with`.
    ///
    /// This additive prototype intentionally delegates cryptographic behavior to
    /// [`NegotiatedAuthoritySession::accept_operator_rekey_proposal`]. The final
    /// reconstructed receiver should make this ownership shape the primary API
    /// after strict expected-domain/current-key receive is integrated.
    pub fn accept_operator_rekey_proposal_pending(
        self,
        sealed_proposal: &[u8],
    ) -> Result<AuthorityRekeyAckDeliveryPending, AuthorityRekeyRejected> {
        let mut authority = self;
        match authority.accept_operator_rekey_proposal(sealed_proposal) {
            Ok(acceptance) => Ok(AuthorityRekeyAckDeliveryPending {
                authority,
                acceptance,
            }),
            Err(error) => Err(AuthorityRekeyRejected {
                authority: Box::new(authority),
                error,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Session;
    use crate::WireError;
    use crate::authority_negotiation::causal_authority_draft04_capability;
    use crate::authority_session::AuthenticatedNegotiatedHandshake;
    use crate::handshake::SessionKeySchedule;
    use crate::handshake_v2_contract::compose_v5_context;
    use crate::negotiated_context::{
        CapabilityOfferEntryV1, CapabilityOfferV1, negotiate_capabilities,
    };
    use crate::negotiation_policy::NegotiationPolicyV1;
    use crate::operator_rekey::{
        OperatorRekeyMessage, OperatorRekeyReason, PAYLOAD_TYPE_OPERATOR_REKEY,
    };
    use core::future::Future;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    const AEAD: [u8; 32] = [0x55; 32];
    const REKEY_ROOT: [u8; 32] = [0x35; 32];
    const SOURCE_ID: [u8; 8] = *b"authop01";
    const SESSION_EPOCH: u8 = 0x44;

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    struct PendingSend {
        _ack: PendingAuthorityOperatorRekeyAck,
        dropped: Arc<AtomicBool>,
    }

    impl Future for PendingSend {
        type Output = Result<(), &'static str>;

        fn poll(
            self: core::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingSend {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn authority() -> NegotiatedAuthoritySession {
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
        let negotiation = negotiate_capabilities(&host, &viewer).unwrap();
        let base_v4 = ::core::array::from_fn(|index| index as u8);
        let v5 = compose_v5_context(&base_v4, &negotiation.binding_hash());
        let schedule = SessionKeySchedule {
            aead: AEAD,
            control: [0x31; 32],
            video: [0x32; 32],
            audio: [0x33; 32],
            telemetry: [0x34; 32],
            rekey: REKEY_ROOT,
            context: [0x36; 32],
            transcript_hash: [0x11; 32],
            host_identity_fingerprint: [0x22; 32],
        };
        let proof = AuthenticatedNegotiatedHandshake::from_verified_v2_parts(
            host, viewer, base_v4, v5, schedule,
        )
        .unwrap();
        let installed = proof
            .install_into(Session::with_source_id(SOURCE_ID, SESSION_EPOCH))
            .unwrap();
        let policy =
            NegotiationPolicyV1::minimum_required([causal_authority_draft04_capability()]).unwrap();
        installed.narrow_to_causal_authority(&policy).unwrap()
    }

    fn seal_operator_message(key: [u8; 32], message: &OperatorRekeyMessage) -> Vec<u8> {
        let mut sender = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
        sender.install_key(key);
        sender
            .seal(&message.encode().unwrap(), PAYLOAD_TYPE_OPERATOR_REKEY)
            .unwrap()
    }

    fn valid_epoch_one_proposal() -> OperatorRekeyMessage {
        crate::operator_rekey::propose(
            1,
            [0x11; 32],
            [0x11; 32],
            OperatorRekeyReason::Manual,
        )
        .unwrap()
    }

    #[test]
    fn semantic_rejection_returns_session_without_replay_rollback() {
        let authority = authority();
        let unexpected_ack = OperatorRekeyMessage::Ack {
            key_epoch: 1,
            epoch_hash: [0x77; 32],
        };
        let sealed = seal_operator_message(AEAD, &unexpected_ack);

        let rejected = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap_err();
        assert!(matches!(
            rejected.error(),
            &AuthorityOperatorRekeyError::UnexpectedAck
        ));
        let (mut authority, error) = rejected.into_parts();
        assert!(matches!(error, AuthorityOperatorRekeyError::UnexpectedAck));

        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed),
            Err(AuthorityOperatorRekeyError::Wire(WireError::OpenFailed))
        ));
    }

    #[test]
    fn one_successful_transport_continuation_reactivates_new_epoch_authority() {
        let authority = authority();
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap();
        let calls = Cell::new(0usize);

        let result = block_on_ready(pending.resolve_with(|ack| {
            calls.set(calls.get() + 1);
            let bytes = ack.into_bytes();
            assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
            core::future::ready(Ok::<(), &'static str>(()))
        }));
        assert_eq!(calls.get(), 1);

        let (authority, transition, lineage) = match result {
            Ok(value) => value,
            Err(_) => panic!("successful transport continuation became ambiguous"),
        };
        assert_eq!(transition.key_epoch, 1);
        assert_eq!(lineage.key_epoch, 1);
        assert_eq!(authority.lineage(), &lineage);
        assert_eq!(authority.session().nonce_counter(), 1);
    }

    #[test]
    fn one_failed_transport_continuation_returns_terminal_evidence_only() {
        let authority = authority();
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap();
        let calls = Cell::new(0usize);

        let result = block_on_ready(pending.resolve_with(|ack| {
            calls.set(calls.get() + 1);
            let bytes = ack.into_bytes();
            assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
            core::future::ready(Err::<(), _>("carrier outcome ambiguous"))
        }));
        assert_eq!(calls.get(), 1);

        let ambiguous = match result {
            Err(error) => error,
            Ok(_) => panic!("failed transport continuation reactivated authority"),
        };
        assert_eq!(ambiguous.transport_error(), &"carrier outcome ambiguous");
        assert_eq!(ambiguous.transition().key_epoch, 1);
        assert_eq!(ambiguous.lineage().key_epoch, 1);
        let (error, transition, lineage) = ambiguous.into_parts();
        assert_eq!(error, "carrier outcome ambiguous");
        assert_eq!(transition.key_epoch, 1);
        assert_eq!(lineage.key_epoch, 1);
    }

    #[test]
    fn cancelling_unresolved_transport_continuation_drops_ack_capability() {
        let authority = authority();
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap();
        let calls = Cell::new(0usize);
        let transport_future_dropped = Arc::new(AtomicBool::new(false));
        let dropped = Arc::clone(&transport_future_dropped);

        let mut future = Box::pin(pending.resolve_with(|ack| {
            calls.set(calls.get() + 1);
            PendingSend {
                _ack: ack,
                dropped,
            }
        }));

        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(calls.get(), 1);
        assert!(!transport_future_dropped.load(Ordering::SeqCst));

        // Cancelling the unresolved outer future drops the inner transport
        // future, which owns the one Ack capability. The committed authority
        // session is likewise owned only by the outer future and cannot be
        // recovered through the safe API after this point.
        drop(future);
        assert!(transport_future_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn explicit_dead_carrier_teardown_returns_only_durable_evidence() {
        let authority = authority();
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority
            .accept_operator_rekey_proposal_pending(&sealed)
            .unwrap();

        let (transition, lineage) = pending.into_ambiguous_evidence();
        assert_eq!(transition.key_epoch, 1);
        assert_eq!(lineage.key_epoch, 1);
    }
}
