# ReplayWindow Kani Profile V1

Tracking: #69 / #70.

## Purpose

Use Kani as a bounded implementation-safety lane for the canonical `xenia-wire` replay window without confusing bounded model checking with an unbounded protocol theorem.

Exact subject at profile freeze:

```text
repo   Luminous-Dynamics/xenia-wire
commit 057dd03043b8863d8f8280abf333331cc9ddf317
path   src/replay_window.rs
blob   9e55ddf7bfd7d7851cc3968d3407bd2c78ba9908
```

Kani profile:

```text
version 0.67.0
upstream commit 4feaaad1d6a2378a6ff6caa3b4fc5d6999c7bb5d
```

## V1 bounds

```text
window widths       64, 128 bits
trace steps         <= 4
stream identities   <= 2
sequence values     symbolic u64 per step
```

The executable child must retain the exact per-harness unwind bound. A failed unwinding assertion means the property was not established and blocks `Pass`.

## Constructor boundary

`ReplayWindow::with_window_bits` intentionally panics outside:

```text
64 <= bits <= 1024
bits % 64 == 0
```

Therefore V1 proves/checks safety **under admitted configuration**. It must not claim universal panic freedom for invalid configuration calls.

## Verification strategy

Attempt the production `ReplayWindow` path first.

If the `HashMap`/`Vec` implementation is unsupported or intractable under the frozen bounds, the acceptable fallback is a small **production-used** pure transition seam. A copied verification-only algorithm is forbidden because proving it would not prove the implementation used at runtime.

## Complementary evidence

```text
unit tests
+ proptests
+ fuzz_replay_window
+ Kani bounded model safety
+ future deductive/Verus transition proof
```

None inherits the evidence class of another.

## Canonical result mapping

```text
all selected harnesses verified with sufficient bounds -> Pass
counterexample / reachable safety violation             -> Fail
insufficient unwind / required semantics unsupported    -> Blocked
tool setup or executor failure                          -> EnvironmentFailure
```

Kani-specific details remain diagnostic metadata rather than replacing the canonical state.

## Nonclaims

```text
Kani bounded PASS
!= unbounded replay correctness
!= liveness
!= cryptographic authenticity
!= nonce uniqueness
!= compiler/native-binary correctness
!= cross-repository proof portability
```

This profile freezes the proof search boundary. It does not implement or execute the Kani harnesses; the next child owns that work.