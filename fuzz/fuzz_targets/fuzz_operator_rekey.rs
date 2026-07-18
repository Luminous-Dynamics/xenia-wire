// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `OperatorRekeyMessage::decode()` with arbitrary input. This
//! is the sealed control payload's decode step for the operator channel's
//! own single-key rekey -- reached after AEAD open succeeds, so the bytes
//! are authenticated, but a confused/desynced sender or a future codec bug
//! still shouldn't be able to panic the receiver.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::operator_rekey::OperatorRekeyMessage;

fuzz_target!(|data: &[u8]| {
    let _ = OperatorRekeyMessage::decode(data);
});
