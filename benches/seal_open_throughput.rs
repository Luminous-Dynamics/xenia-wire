// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Criterion bench: seal/open throughput on a 4 KB frame.
//!
//! Run with: `cargo bench --bench seal_open_throughput`

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use xenia_wire::{open_frame, seal_frame, Frame, Session};

fn make_frame(size: usize) -> Frame {
    Frame {
        frame_id: 1,
        timestamp_ms: 1_700_000_000_000,
        payload: (0..size as u32).map(|i| (i & 0xFF) as u8).collect(),
    }
}

fn paired_sessions(key: [u8; 32]) -> (Session, Session) {
    let mut sender = Session::new();
    let mut receiver = Session::new();
    sender.install_key(key);
    receiver.install_key(key);
    (sender, receiver)
}

fn bench_seal(c: &mut Criterion) {
    let frame = make_frame(4096);
    let (mut sender, _) = paired_sessions([0xAB; 32]);

    let mut group = c.benchmark_group("seal");
    group.throughput(Throughput::Bytes(4096));
    group.bench_function("frame_4KB", |b| {
        b.iter(|| {
            let out = seal_frame(black_box(&frame), &mut sender).unwrap();
            black_box(out);
        })
    });
    group.finish();
}

fn bench_seal_open(c: &mut Criterion) {
    let frame = make_frame(4096);
    let (mut sender, mut receiver) = paired_sessions([0xCD; 32]);

    let mut group = c.benchmark_group("seal_open");
    group.throughput(Throughput::Bytes(4096));
    group.bench_function("roundtrip_4KB", |b| {
        b.iter(|| {
            let sealed = seal_frame(black_box(&frame), &mut sender).unwrap();
            let opened = open_frame(&sealed, &mut receiver).unwrap();
            black_box(opened);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_seal, bench_seal_open);
criterion_main!(benches);
