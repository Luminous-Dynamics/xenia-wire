// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Pre-commit transport-reservation ownership for receiver authority rekey.
//!
//! [`crate::authority_rekey_pending`] closes the post-commit authority gap: once
//! Wire commits a new receiver key/lineage, active authority is trapped inside an
//! Ack-delivery typestate until one transport continuation resolves. Cross-repo
//! composition with xenia-peer exposed an earlier race, however: if the peer only
//! acquires its exclusive ordered writer *after* Wire returns the committed
//! pending state, an application sender can win that writer in the gap.
//!
//! This module is an additive prototype that makes the required ordering visible
//! in Rust ownership. The peer acquires an opaque, non-duplicated transport
//! reservation first and moves it into
//! [`NegotiatedAuthoritySession::accept_operator_rekey_proposal_reserved`]. Wire
//! then carries that reservation across the receiver transaction:
//!
//! ```text
//! peer acquires exclusive ordered writer reservation
//!     -> reservation moves into Wire accept
//!     -> pre-commit reject: reservation + still-live session return together
//!     -> post-commit success: reservation + authority + exact Ack stay trapped
//!        in one pending typestate
//!     -> one transport continuation consumes reservation + exact Ack
//!     -> success returns active authority | ambiguity destroys authority
//! ```
//!
//! xenia-wire cannot prove that an external reservation really represents a
//! carrier ordering lock; the concrete peer adapter remains part of the transport
//! TCB. To make that trust boundary explicit, reservation types must implement
//! [`AuthorityRekeyWriterReservation`]. There is intentionally no blanket
//! implementation. Rust's orphan rules therefore force xenia-peer to define a
//! local wrapper around its real writer guard and explicitly opt that wrapper into
//! this contract instead of accidentally passing `()`, a primitive, or an
//! unrelated foreign guard directly.
//!
//! The post-commit wrapper deliberately stores Wire's pending authority field
//! before the writer reservation. Ordinary struct drop therefore destroys the
//! pending Wire authority/Ack state before releasing the reservation and waking a
//! possible competing writer. Explicit ambiguity follows the same order. Async
//! cancellation while already inside the transport continuation still requires
//! the peer's connection-generation barrier/fail-closed reservation semantics;
//! this prototype does not claim to control scheduler interleavings between
//! independently owned peer tasks.
//!
//! ```compile_fail
//! use xenia_wire::authority_rekey_reserved::AuthorityRekeyWriterReservation;
//!
//! fn requires_writer_reservation<R: AuthorityRekeyWriterReservation>(_reservation: R) {}
//!
//! requires_writer_reservation(()); // no implicit/blanket reservation implementation
//! ```

#![cfg(all(
    feature = "causal-authority",
    feature = "handshake",
    feature = "operator-rekey"
))]

use core::fmt;
use core::future::Future;

use crate::authority_lineage_epoch_evidence::AuthorityLineageEpochEvidenceV1;
use crate::authority_rekey_pending::{
    AuthorityRekeyAckDeliveryAmbiguous, AuthorityRekeyAckDeliveryPending,
    AuthorityRekeyRejected,
};
use crate::authority_rekey_transition_evidence::AuthorityRekeyTransitionEvidenceV1;
use crate::authority_session::{
    AuthorityOperatorRekeyError, NegotiatedAuthoritySession, PendingAuthorityOperatorRekeyAck,
};

/// Explicit adapter contract for a peer-owned reservation of the ordered writer
/// that must remain unavailable to competing traffic across receiver rekey.
///
/// This trait intentionally has no blanket implementations. A transport crate
/// should implement it only for a local, non-`Clone` wrapper whose ownership
/// actually excludes competing authority/application writers in the relevant
/// carrier ordering domain. Implementing the trait is an auditable TCB decision;
/// the trait itself cannot prove the transport semantics.
pub trait AuthorityRekeyWriterReservation {}

/// Pre-commit receiver-rekey rejection with the caller's transport reservation
/// returned alongside the still-live authority session.
///
/// Returning the reservation is safe because the underlying Wire receiver did
/// not cross its commit boundary. Authenticated semantic rejection may still have
/// consumed replay state; the returned session preserves that consumed state.
#[must_use = "a rejected reserved receiver rekey returns both writer reservation and live authority"]
pub struct AuthorityRekeyReservedRejected<R: AuthorityRekeyWriterReservation> {
    reservation: Box<R>,
    rejection: AuthorityRekeyRejected,
}

impl<R: AuthorityRekeyWriterReservation> AuthorityRekeyReservedRejected<R> {
    /// Underlying Wire rejection without releasing either owned capability.
    pub fn error(&self) -> &AuthorityOperatorRekeyError {
        self.rejection.error()
    }

    /// Recover the pre-commit transport reservation, still-live authority
    /// session, and exact rejection reason.
    pub fn into_parts(
        self,
    ) -> (R, NegotiatedAuthoritySession, AuthorityOperatorRekeyError) {
        let (authority, error) = self.rejection.into_parts();
        (*self.reservation, authority, error)
    }
}

impl<R: AuthorityRekeyWriterReservation> fmt::Debug for AuthorityRekeyReservedRejected<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyReservedRejected")
            .field("error", self.error())
            .finish_non_exhaustive()
    }
}

/// Post-commit receiver-rekey state that owns both Wire's Ack-delivery pending
/// authority and the peer's already-acquired ordered-writer reservation.
///
/// Wire pending authority is intentionally the first field so ordinary drop
/// destroys authority/Ack before releasing the writer reservation. A real peer
/// integration should use a non-`Clone` reservation whose ownership excludes
/// every competing authority/application writer in the same ordering domain.
#[must_use = "reserved receiver rekey must resolve Ack delivery or terminate the connection generation"]
pub struct AuthorityRekeyReservedAckDeliveryPending<R: AuthorityRekeyWriterReservation> {
    pending: AuthorityRekeyAckDeliveryPending,
    reservation: R,
}

impl<R: AuthorityRekeyWriterReservation> AuthorityRekeyReservedAckDeliveryPending<R> {
    /// Durable public evidence for the committed authority transition.
    pub fn transition(&self) -> &AuthorityRekeyTransitionEvidenceV1 {
        self.pending.transition()
    }

    /// Durable authority-lineage position after the committed transition.
    pub fn lineage(&self) -> &AuthorityLineageEpochEvidenceV1 {
        self.pending.lineage()
    }

    /// Resolve the committed Ack barrier through exactly one continuation that
    /// receives *both* the pre-commit transport reservation and the exact
    /// presealed Ack capability by value.
    ///
    /// The concrete transport continuation is responsible for using the supplied
    /// reservation as the exclusive ordered carrier writer and for returning
    /// `Ok(())` only after its defined local handoff condition is satisfied.
    /// xenia-wire cannot prove those transport semantics; it does guarantee that
    /// safe caller code cannot reacquire the reservation between Wire commit and
    /// this continuation.
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
        F: FnOnce(R, PendingAuthorityOperatorRekeyAck) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let Self {
            pending,
            reservation,
        } = self;
        pending
            .resolve_with(|pending_ack| send_once(reservation, pending_ack))
            .await
    }

    /// Fail closed without attempting Ack delivery.
    ///
    /// Wire's owned active authority session and Ack capability are destroyed
    /// first. Only then is the transport reservation released. Durable transition
    /// and lineage evidence are the only outputs.
    pub fn into_ambiguous_evidence(
        self,
    ) -> (
        AuthorityRekeyTransitionEvidenceV1,
        AuthorityLineageEpochEvidenceV1,
    ) {
        let Self {
            pending,
            reservation,
        } = self;
        let evidence = pending.into_ambiguous_evidence();
        drop(reservation);
        evidence
    }
}

impl<R: AuthorityRekeyWriterReservation> fmt::Debug
    for AuthorityRekeyReservedAckDeliveryPending<R>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRekeyReservedAckDeliveryPending")
            .field("transition", self.transition())
            .field("lineage", self.lineage())
            .finish_non_exhaustive()
    }
}

impl NegotiatedAuthoritySession {
    /// Consume this active authority session only after the caller has already
    /// acquired the transport ordering reservation that must span receiver commit
    /// through exact Ack handoff.
    ///
    /// - pre-commit rejection returns reservation + live authority + error;
    /// - post-commit success returns only a reserved pending typestate that owns
    ///   the reservation together with Wire's committed authority/Ack state.
    pub fn accept_operator_rekey_proposal_reserved<R: AuthorityRekeyWriterReservation>(
        self,
        reservation: R,
        sealed_proposal: &[u8],
    ) -> Result<
        AuthorityRekeyReservedAckDeliveryPending<R>,
        AuthorityRekeyReservedRejected<R>,
    > {
        match self.accept_operator_rekey_proposal_pending(sealed_proposal) {
            Ok(pending) => Ok(AuthorityRekeyReservedAckDeliveryPending {
                pending,
                reservation,
            }),
            Err(rejection) => Err(AuthorityRekeyReservedRejected {
                reservation: Box::new(reservation),
                rejection,
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    const AEAD: [u8; 32] = [0x55; 32];
    const REKEY_ROOT: [u8; 32] = [0x35; 32];
    const SOURCE_ID: [u8; 8] = *b"authop01";
    const SESSION_EPOCH: u8 = 0x44;

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    #[derive(Debug)]
    struct ReservationProbe {
        dropped: Arc<AtomicBool>,
    }

    impl AuthorityRekeyWriterReservation for ReservationProbe {}

    impl Drop for ReservationProbe {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct PendingReservedSend {
        _reservation: ReservationProbe,
        _ack: PendingAuthorityOperatorRekeyAck,
    }

    impl Future for PendingReservedSend {
        type Output = Result<(), &'static str>;

        fn poll(
            self: core::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            Poll::Pending
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
    fn precommit_rejection_returns_reservation_and_live_session() {
        let dropped = Arc::new(AtomicBool::new(false));
        let reservation = ReservationProbe {
            dropped: Arc::clone(&dropped),
        };
        let unexpected_ack = OperatorRekeyMessage::Ack {
            key_epoch: 1,
            epoch_hash: [0x77; 32],
        };
        let sealed = seal_operator_message(AEAD, &unexpected_ack);

        let rejected = authority()
            .accept_operator_rekey_proposal_reserved(reservation, &sealed)
            .unwrap_err();
        assert!(matches!(
            rejected.error(),
            &AuthorityOperatorRekeyError::UnexpectedAck
        ));
        assert!(!dropped.load(Ordering::SeqCst));

        let (reservation, mut authority, error) = rejected.into_parts();
        assert!(matches!(error, AuthorityOperatorRekeyError::UnexpectedAck));
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(matches!(
            authority.accept_operator_rekey_proposal(&sealed),
            Err(AuthorityOperatorRekeyError::Wire(WireError::OpenFailed))
        ));
        drop(reservation);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn success_hands_reservation_and_exact_ack_to_one_continuation() {
        let dropped = Arc::new(AtomicBool::new(false));
        let reservation = ReservationProbe {
            dropped: Arc::clone(&dropped),
        };
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority()
            .accept_operator_rekey_proposal_reserved(reservation, &sealed)
            .unwrap();

        let (authority, transition, lineage) = block_on_ready(pending.resolve_with(
            |reservation, ack| async move {
                assert_eq!(&ack.as_bytes()[8..12], &[0, 0, 0, 0]);
                drop(reservation);
                Ok::<(), &'static str>(())
            },
        ))
        .unwrap();

        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(transition.key_epoch, 1);
        assert_eq!(lineage.key_epoch, 1);
        assert_eq!(authority.lineage(), &lineage);
        assert_eq!(authority.session().nonce_counter(), 1);
    }

    #[test]
    fn cancellation_drops_reservation_with_unresolved_ack_continuation() {
        let dropped = Arc::new(AtomicBool::new(false));
        let reservation = ReservationProbe {
            dropped: Arc::clone(&dropped),
        };
        let proposal = valid_epoch_one_proposal();
        let sealed = seal_operator_message(AEAD, &proposal);
        let pending = authority()
            .accept_operator_rekey_proposal_reserved(reservation, &sealed)
            .unwrap();

        let mut future = Box::pin(pending.resolve_with(|reservation, ack| PendingReservedSend {
            _reservation: reservation,
            _ack: ack,
        }));
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        assert!(!dropped.load(Ordering::SeqCst));

        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
