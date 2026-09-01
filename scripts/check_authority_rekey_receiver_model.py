#!/usr/bin/env python3
"""Bounded exhaustive model for the authority-preserving operator rekey receiver.

The model captures the intended successor of authority rekey PR #41 when
composed with strict expected nonce-domain receive (#40) and a future
current-key-only Session receive primitive (#38).

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


@dataclass(frozen=True, order=True)
class State:
    active_key_epoch: int = 0
    authority_lineage_epoch: int = 0
    replay_slots_consumed: int = 0
    outbound_nonce_counter: int = 0
    expected_peer_domain_version: int = 1
    local_sender_domain_version: int = 1
    accepted_transition_count: int = 0


@dataclass(frozen=True)
class Outcome:
    state: State
    rejected: bool
    rejection_stage: str | None
    replay_consumed_this_call: bool
    ack_sequence: int | None


MAX_ACCEPTED_TRANSITIONS = 3


def events(state: State) -> tuple[Event, ...]:
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


def transact(state: State, event: Event) -> Outcome:
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
    replayed = State(
        active_key_epoch=state.active_key_epoch,
        authority_lineage_epoch=state.authority_lineage_epoch,
        replay_slots_consumed=state.replay_slots_consumed + 1,
        outbound_nonce_counter=state.outbound_nonce_counter,
        expected_peer_domain_version=state.expected_peer_domain_version,
        local_sender_domain_version=state.local_sender_domain_version,
        accepted_transition_count=state.accepted_transition_count,
    )

    if event is Event.CURRENT_KEY_SEMANTIC_INVALID:
        return Outcome(replayed, True, "semantic_validation", True, None)

    # Ack encoding/preseal is the final fallible stage. Failure keeps the active
    # key, lineage, and outbound nonce state unchanged, while preserving the live
    # replay consumption of the authenticated rejected Proposal.
    if event is Event.CURRENT_KEY_ACK_PRESEAL_FAILS:
        return Outcome(replayed, True, "ack_preseal", True, None)

    if event is Event.CURRENT_KEY_VALID:
        committed = State(
            active_key_epoch=state.active_key_epoch + 1,
            authority_lineage_epoch=state.authority_lineage_epoch + 1,
            replay_slots_consumed=state.replay_slots_consumed + 1,
            # New-key Ack is presealed at sequence zero before commit; the live
            # new-key sender starts at one after the infallible commit boundary.
            outbound_nonce_counter=1,
            expected_peer_domain_version=state.expected_peer_domain_version,
            local_sender_domain_version=state.local_sender_domain_version,
            accepted_transition_count=state.accepted_transition_count + 1,
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
    # on the fully valid transaction.
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

    if event is Event.CURRENT_KEY_VALID:
        assert after.replay_slots_consumed == before.replay_slots_consumed + 1
        assert after.accepted_transition_count == before.accepted_transition_count + 1


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
        "states": [
            asdict(state)
            for state in sorted(states)
        ],
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
            "Bounded exhaustive abstract transaction exploration. This branch does "
            "not yet implement Session current-key-only receive or #40 composition."
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
            "key and authority lineage advance together only after fully valid transaction",
            "successful Ack is reserved at new-key sequence zero and live sender continues at one",
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
