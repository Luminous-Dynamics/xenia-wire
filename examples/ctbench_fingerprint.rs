// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! DudeCT statistical constant-time verification for [`ct_eq_32`], the
//! 32-byte comparison primitive `Session::verify_fingerprint_either_epoch`
//! uses to check a signed fingerprint against the current key (and, during
//! a rekey grace window, the previous key too). `src/session.rs`'s own doc
//! comment already identifies why this specific comparison is
//! timing-sensitive: a naive early-return implementation would let a
//! remote observer of verify-path latency learn which key-epoch a peer
//! signed under, which is sensitive metadata about session state near a
//! rekey. `ct_eq_32` was hand-written (a bitwise-OR accumulate loop, no
//! data-dependent branch) specifically to avoid that -- this benchmark
//! checks that claim empirically rather than trusting the code comment.
//!
//! [`ct_eq_32`]: crate hidden, see [`xenia_wire::ct_eq_32_for_bench`]
//!
//! Requires the normally-private primitive to be re-exposed; see
//! `ct_eq_32_for_bench`'s own doc comment in `src/session.rs` for why that's
//! gated behind `bench-internals` rather than always public.
//!
//! Run:
//! ```sh
//! cargo run --release --example ctbench_fingerprint --features consent,bench-internals
//! ```
//!
//! Interpretation (DudeCT's own convention, not specific to this crate): the
//! printed `max t` statistic is a t-test comparing the two timing
//! distributions. A value below ~5 is the accepted threshold for "no
//! statistically significant timing difference found" -- i.e. consistent
//! with constant-time behavior (this is evidence, not a formal proof: a
//! clean run doesn't rule out a leak too small for this sample size to
//! detect). A value at or above 5 would indicate a real, measurable timing
//! difference between the two input classes below.

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use rand_core::Rng;
use xenia_wire::ct_eq_32_for_bench;

fn rand_32(rng: &mut BenchRng) -> [u8; 32] {
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    buf
}

/// `Left` distribution: two 32-byte arrays that are equal (the "fingerprint
/// matches" case -- the common, steady-state path in
/// `verify_fingerprint_either_epoch`). `Right` distribution: two arrays that
/// differ in exactly one byte, at a randomly chosen position each time (the
/// "fingerprint doesn't match this key" case -- hit once per key tried
/// during the rekey grace window, and always hit for a forged/stale
/// fingerprint). If `ct_eq_32` is genuinely constant-time, these two
/// distributions should be statistically indistinguishable by timing alone
/// -- in particular, timing must not correlate with *where* the mismatch
/// falls, which is exactly what an early-return implementation would leak.
fn fingerprint_compare(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(100_000);
    let mut classes: Vec<Class> = Vec::with_capacity(100_000);

    for _ in 0..100_000 {
        let mut selector = [0u8; 1];
        rng.fill_bytes(&mut selector);
        let a = rand_32(rng);
        if selector[0] & 1 == 0 {
            let b = a;
            inputs.push((a, b));
            classes.push(Class::Left);
        } else {
            let mut b = a;
            let mut pos = [0u8; 1];
            rng.fill_bytes(&mut pos);
            let idx = (pos[0] as usize) % 32;
            b[idx] ^= 0xFF;
            inputs.push((a, b));
            classes.push(Class::Right);
        }
    }

    for (class, (a, b)) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || ct_eq_32_for_bench(&a, &b));
    }
}

ctbench_main!(fingerprint_compare);
