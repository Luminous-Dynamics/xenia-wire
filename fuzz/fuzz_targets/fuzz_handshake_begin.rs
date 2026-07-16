// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `ViewerHandshake::begin()` with arbitrary input.
//!
//! `begin()` is the real network-facing entry point for a `HostHello`
//! envelope -- a viewer (browser or native) calls it on whatever bytes a
//! daemon (possibly hostile, possibly a MITM) sent first, before any
//! authentication has happened. Goal: no panic on any byte sequence.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::handshake::ViewerHandshake;

fuzz_target!(|data: &[u8]| {
    let mut viewer = ViewerHandshake::new();
    let _ = viewer.begin(data);
});
