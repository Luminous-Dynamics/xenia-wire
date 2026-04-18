// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `ReplayWindow::accept()` with adversarial sequence
//! patterns. Exercises the window shift / bitmap update arithmetic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::ReplayWindow;

fuzz_target!(|data: &[u8]| {
    // Split `data` into (source_id, payload_type, key_epoch, seq)
    // quads. Exercises the sliding-window + per-key-epoch scoping
    // introduced in alpha.4 (SPEC §5.3).
    let mut w = ReplayWindow::new();
    let chunk_size = 8 + 1 + 1 + 8; // u64 + u8 + u8 + u64
    for chunk in data.chunks(chunk_size) {
        if chunk.len() < chunk_size {
            break;
        }
        let source_id = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let payload_type = chunk[8];
        let key_epoch = chunk[9];
        let seq = u64::from_le_bytes(chunk[10..18].try_into().unwrap());
        let _ = w.accept(source_id, payload_type, key_epoch, seq);
    }
});
