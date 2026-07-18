// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `ViewerHandshakeHighSec::begin()` with arbitrary input.
//! Same rationale as `fuzz_handshake_begin`, for the ML-KEM-1024 +
//! ML-DSA-87 high-security suite.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::handshake_highsec::ViewerHandshakeHighSec;

fuzz_target!(|data: &[u8]| {
    let mut viewer = ViewerHandshakeHighSec::new();
    let _ = viewer.begin(data);
});
