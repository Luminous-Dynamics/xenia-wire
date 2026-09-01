#!/usr/bin/env python3
"""Bounded exhaustive model for the authority-preserving operator rekey receiver.

The model captures the intended successor of authority rekey PR #41 when
composed with strict expected nonce-domain receive (#40), a future current-key-
only Session receive primitive (#38), and the transport-owned Ack delivery
boundary that follows Wire's preseal-before-commit transaction.

It deliberately models the transaction contract independently from production
Rust. It is design evidence, not a proof that an implementation satisfies the
model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class Event(str, Enum):
    WRONG_PEER_DOMAIN = "wrong_peer_domain"
    CALLER_DOMAIN_SUBSTITUTION = "caller_domain_substitution"
    PREVIOUS_KEY_ONLY = "previous_key_only"
    WRONG_CURRENT_KEY = "wrong_current_key"
    CURRENT_KEY_SEMANTIC_INVALID = "current_key_semantic_invalid"
    CURRENT_KEY_ACK_PRESEAL_FAILS = "current_key_ack_preseal_fails"
    CURRENT_KEY_VALID = "current_key_valid"
    REPLAY_LAST_ACCEPTED = "replay_last_accepted"
    ACK_SEND_SUCCESS = "ack_send_success"
    ACK_SEND_FAIL_BEFORE_WRITE = "ack_send_fail_before_write"
    ACK_SEND_FAIL_AFTER_WRITE = "ack_send_fail_after_write"


@dataclass(frozen=True, order=True)
class State:
    active_key_epoch: int = 0
    authority_lineage_epoch: int = 0
    replay_slots_consumed: int = 0
    outbound_nonce_counter: int = 0
    expected_peer_domain_version: int = 1
    local_sender_domain_version: int = 1
    accepted_transition_count: int = 0
    ack_delivery_pending: bool = False
    connection_live: bool = True
    application_authority: bool = True


@dataclass(frozen=True)
class Outcome:
    state: State
    rejected: bool
    rejection_stage: str | None
    replay_consumed_this_call: bool
    ack_sequence: int | None


MAX_ACCEPTED_TRANSITIONS = 3


def events(state: State) -> tuple[Event, ...]:
    # A transport failure is terminal for the current connection generation.
    if not state.connection_live:
        return tuple()

    # Once Wire has committed and returned an Ack, no other authority-bearing
    # operation may interleave before the transport owner resolves that exact
    # presealed Ack's single send attempt.
    if state.ack_delivery_pending:
        return (
            Event.ACK_SEND_SUCCESS,
            Event.ACK_SEND_FAIL_BEFORE_WRITE,
            Event.ACK_SEND_FAIL_AFTER_WRITE,
        )

    base = (
        Event.WRONG_PEER_DOMAIN,
        Event.CALLER_DOMAIN_SUBSTITUTION,
        Event.PREVIOUS_KEY_ONLY,
        Event.WRONG_CURRENT_KEY,
        Event.CURRENT_KEY_SEMANTIC_INVALID,
        Event.CURRENT_KEY_ACK_PRESEAL_FAILS,
        Event.REPLAY_LAST_ACCEPTED,
    )
    if state.accepted_transition_count < MAX_ACCEPTED_TRANSITIONS:
        return base + (Event.CURRENT_KEY_VALID,)
    return base


def _copy_state(
    state: State,
    *,
    active_key_epoch: int | None = None,
    authority_lineage_epoch: int | None = None,
    replay_slots_consumed: int | None = None,
    outbound_nonce_counter: int | None = None,
    accepted_transition_count: int | None = None,
    ack_delivery_pending: bool | None = None,
    connection_live: bool | None = None,
    application_authority: bool | None = None,
) -> State:
    return State(
        active_key_epoch=(
            state.active_key_epoch if active_key_epoch is None else active_key_epoch
        ),
        authority_lineage_epoch=(
            state.authority_lineage_epoch
            if authority_lineage_epoch is None
            else authority_lineage_epoch
        ),
        replay_slots_consumed=(
            state.replay_slots_consumed
            if replay_slots_consumed is None
            else replay_slots_consumed
        ),
        outbound_nonce_counter=(
            state.outbound_nonce_counter
            if outbound_nonce_counter is None
            else outbound_nonce_counter
        ),
        expected_peer_domain_version=state.expected_peer_domain_version,
        local_sender_domain_version=state.local_sender_domain_version,
        accepted_transition_count=(
            state.accepted_transition_count
            if accepted_transition_count is None
            else accepted_transition_count
        ),
        ack_delivery_pending=(
            state.ack_delivery_pending
            if ack_delivery_pending is None
            else ack_delivery_pending
        ),
        connection_live=(
            state.connection_live if connection_live is None else connection_live
        ),
        application_authority=(
            state.application_authority
            if application_authority is None
            else application_authority
        ),
    )


def transact(state: State, event: Event) -> Outcome:
    if not state.connection_live:
        raise AssertionError("dead connection cannot process further events")

    if state.ack_delivery_pending:
        if event is Event.ACK_SEND_SUCCESS:
            delivered = _copy_state(
                state,
                ack_delivery_pending=False,
                application_authority=True,
            )
            return Outcome(delivered, False, None, False, None)

        if event in (
            Event.ACK_SEND_FAIL_BEFORE_WRITE,
            Event.ACK_SEND_FAIL_AFTER_WRITE,
        ):
            dead = _copy_state(
                state,
                ack_delivery_pending=False,
                connection_live=False,
                application_authority=False,
            )
            return Outcome(dead, True, "ack_transport", False, None)

        raise AssertionError(f"event {event} interleaved while Ack delivery was pending")

    # Strict peer-domain binding is checked before any decrypt/replay mutation.
    if event in (Event.WRONG_PEER_DOMAIN, Event.CALLER_DOMAIN_SUBSTITUTION):
        return Outcome(state, True, "domain_precheck", False, None)

    # Exact-current-key-only receive rejects previous/grace or unrelated keys
    # before the live replay window is consumed.
    if event in (Event.PREVIOUS_KEY_ONLY, Event.WRONG_CURRENT_KEY):
        return Outcome(state, True, "current_key_authentication", False, None)

    # Replaying a previously accepted envelope is rejected by the live replay
    # window. The already-consumed slot remains consumed but is not counted twice.
    if event is Event.REPLAY_LAST_ACCEPTED:
        return Outcome(state, True, "replay_window", False, None)

    # At this point exact-current-key authentication succeeded and the live replay
    # window consumed the envelope before semantic authority checks.
    replayed = _copy_state(
        state,
        replay_slots_consumed=state.replay_slots_consumed + 1,
    )

    if event is Event.CURRENT_KEY_SEMANTIC_INVALID:
        return Outcome(replayed, True, "semantic_validation", True, None)

    # Ack encoding/preseal is the final fallible stage inside Wire. Failure keeps
    # the active key, lineage, and outbound nonce state unchanged, while preserving
    # live replay consumption of the authenticated rejected Proposal.
    if event is Event.CURRENT_KEY_ACK_PRESEAL_FAILS:
        return Outcome(replayed, True, "ack_preseal", True, None)

    if event is Event.CURRENT_KEY_VALID:
        committed = _copy_state(
            state,
            active_key_epoch=state.active_key_epoch + 1,
            authority_lineage_epoch=state.authority_lineage_epoch + 1,
            replay_slots_consumed=state.replay_slots_consumed + 1,
            # New-key Ack is presealed at sequence zero before commit; the live
            # new-key sender starts at one after the infallible Wire commit.
            outbound_nonce_counter=1,
            accepted_transition_count=state.accepted_transition_count + 1,
            # The transport owner must resolve delivery of this exact Ack before
            # application authority can resume on this connection.
            ack_delivery_pending=True,
            application_authority=False,
        )
        return Outcome(committed, False, None, True, 0)

    raise AssertionError(f"unhandled event {event}")


def assert_outcome(before: State, event: Event, result: Outcome) -> None:
    after = result.state

    # Immutable role/domain configuration: callers never get to substitute the
    # expected peer domain per operation, and successful rekey does not mutate it.
    assert after.expected_peer_domain_version == before.expected_peer_domain_version
    assert after.local_sender_domain_version == before.local_sender_domain_version

    # Authority key epoch and lineage are lock-step and can advance only together
    # on the fully valid Wire transaction.
    assert after.active_key_epoch == after.authority_lineage_epoch
    delta_key = after.active_key_epoch - before.active_key_epoch
    delta_lineage = after.authority_lineage_epoch - before.authority_lineage_epoch
    assert delta_key == delta_lineage
    assert delta_key in (0, 1)
    if delta_key == 1:
        assert event is Event.CURRENT_KEY_VALID
        assert not result.rejected
        assert result.ack_sequence == 0
        assert after.outbound_nonce_counter == 1
        assert after.ack_delivery_pending
        assert after.connection_live
        assert not after.application_authority

    # A committed Ack awaiting delivery is a distinct non-authoritative state.
    if after.ack_delivery_pending:
        assert after.connection_live
        assert not after.application_authority

    # A reported Ack transport failure kills this connection generation. There
    # is no rollback to the old key/lineage and no same-connection Ack retry.
    if not after.connection_live:
        assert not after.ack_delivery_pending
        assert not after.application_authority
        assert event in (
            Event.ACK_SEND_FAIL_BEFORE_WRITE,
            Event.ACK_SEND_FAIL_AFTER_WRITE,
        )
        assert after.active_key_epoch == before.active_key_epoch
        assert after.authority_lineage_epoch == before.authority_lineage_epoch
        assert after.replay_slots_consumed == before.replay_slots_consumed
        assert after.outbound_nonce_counter == before.outbound_nonce_counter

    # While Ack delivery is pending, exactly one application-level transport
    # outcome resolves it. No semantic/rekey/application operation can interleave.
    if before.ack_delivery_pending:
        assert event in (
            Event.ACK_SEND_SUCCESS,
            Event.ACK_SEND_FAIL_BEFORE_WRITE,
            Event.ACK_SEND_FAIL_AFTER_WRITE,
        )
        assert delta_key == 0
        assert after.replay_slots_consumed == before.replay_slots_consumed
        assert after.outbound_nonce_counter == before.outbound_nonce_counter
        assert not after.ack_delivery_pending
        if event is Event.ACK_SEND_SUCCESS:
            assert after.connection_live
            assert after.application_authority
            assert not result.rejected
        else:
            assert not after.connection_live
            assert not after.application_authority
            assert result.rejected
            assert result.rejection_stage == "ack_transport"
        return

    # Wrong sender role/domain and non-current keys fail before replay mutation.
    if event in (
        Event.WRONG_PEER_DOMAIN,
        Event.CALLER_DOMAIN_SUBSTITUTION,
        Event.PREVIOUS_KEY_ONLY,
        Event.WRONG_CURRENT_KEY,
        Event.REPLAY_LAST_ACCEPTED,
    ):
        assert after.replay_slots_consumed == before.replay_slots_consumed
        assert not result.replay_consumed_this_call
        assert delta_key == 0
        assert after.outbound_nonce_counter == before.outbound_nonce_counter
        assert after.application_authority == before.application_authority

    # Exact-current-key envelopes are replay-consumed even if semantic validation
    # or Ack preseal later rejects them. Authority mutation must remain atomic.
    if event in (
        Event.CURRENT_KEY_SEMANTIC_INVALID,
        Event.CURRENT_KEY_ACK_PRESEAL_FAILS,
    ):
        assert after.replay_slots_consumed == before.replay_slots_consumed + 1
        assert result.replay_consumed_this_call
        assert delta_key == 0
        assert after.outbound_nonce_counter == before.outbound_nonce_counter
        assert after.application_authority == before.application_authority

    if event is Event.CURRENT_KEY_VALID:
        assert after.replay_slots_consumed == before.replay_slots_consumed + 1
        assert after.accepted_transition_count == before.accepted_transition_count + 1
        assert after.ack_delivery_pending
        assert not after.application_authority


def explore(max_depth: int) -> dict:
    initial = State()
    frontier: list[tuple[State, tuple[Event, ...]]] = [(initial, tuple())]
    states = {initial}
    edges: set[tuple[State, Event, State, bool, str | None]] = set()
    prefixes = 1

    for _ in range(max_depth):
        next_frontier: list[tuple[State, tuple[Event, ...]]] = []
        for state, trace in frontier:
            for event in events(state):
                outcome = transact(state, event)
                assert_outcome(state, event, outcome)
                prefixes += 1
                states.add(outcome.state)
                edges.add(
                    (
                        state,
                        event,
                        outcome.state,
                        outcome.rejected,
                        outcome.rejection_stage,
                    )
                )
                next_frontier.append((outcome.state, trace + (event,)))
        frontier = next_frontier

    graph = {
        "states": [asdict(state) for state in sorted(states)],
        "edges": [
            {
                "before": asdict(before),
                "event": event.value,
                "after": asdict(after),
                "rejected": rejected,
                "rejection_stage": stage,
            }
            for before, event, after, rejected, stage in sorted(
                edges,
                key=lambda item: (item[0], item[1].value, item[2], item[3], item[4] or ""),
            )
        ],
    }
    digest = hashlib.sha256(
        json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "schema": "xenia.authority-rekey-receiver-model-report.v1",
        "model": "role-bound-current-key-receiver-successor-v1",
        "claim_boundary": (
            "Bounded exhaustive abstract transaction and Ack-delivery exploration. "
            "This branch does not yet implement Session current-key-only receive, "
            "#40 composition, or transport-owner Ack delivery integration."
        ),
        "max_depth": max_depth,
        "bounded_max_accepted_transitions": MAX_ACCEPTED_TRANSITIONS,
        "checked_trace_prefixes": prefixes,
        "reachable_state_count": len(states),
        "transition_count": len(edges),
        "state_graph_sha256": digest,
        "properties_checked": [
            "expected peer domain is immutable across calls and rekeys",
            "caller domain substitution rejects before replay mutation",
            "wrong peer domain rejects before replay mutation",
            "previous-key-only authentication rejects before replay mutation",
            "semantic-invalid current-key Proposal remains replay-consumed without authority mutation",
            "Ack-preseal failure remains replay-consumed without key/lineage/outbound-nonce mutation",
            "key and authority lineage advance together only after fully valid Wire transaction",
            "successful Ack is reserved at new-key sequence zero and live sender continues at one",
            "application authority remains suspended while the exact presealed Ack awaits its single send outcome",
            "Ack send success resumes authority without changing key/lineage/replay/nonce state",
            "Ack send failure before or after possible byte escape is terminal and never rolls key or lineage back",
            "no application-level Ack reseal or retry can occur after an ambiguous send failure on the same connection",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.max_depth < 1 or args.max_depth > 8:
        raise SystemExit("--max-depth must be between 1 and 8")

    report = explore(args.max_depth)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
