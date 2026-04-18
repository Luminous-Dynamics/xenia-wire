# Fuzzing xenia-wire

Coverage-guided fuzz harness on top of `cargo-fuzz` + `libfuzzer-sys`.
Requires nightly Rust.

## Setup (once)

```console
$ rustup toolchain install nightly
$ cargo install cargo-fuzz
```

## Run a target

```console
$ cargo +nightly fuzz run fuzz_open              -- -max_total_time=300
$ cargo +nightly fuzz run fuzz_open_frame        -- -max_total_time=300
$ cargo +nightly fuzz run fuzz_replay_window     -- -max_total_time=300
$ cargo +nightly fuzz run fuzz_observe_consent   -- -max_total_time=300
```

`-max_total_time=300` runs the target for 5 minutes and exits. Drop
the flag for an open-ended run — cargo-fuzz persists corpus + crash
artifacts under `fuzz/corpus/<target>/` and `fuzz/artifacts/<target>/`.

## Targets

| Target | What it exercises |
|--------|------------------|
| `fuzz_open` | `Session::open()` on arbitrary bytes. Catches panics in nonce parsing, AEAD verify, replay-window keying. |
| `fuzz_open_frame` | `open_frame()` — AEAD + bincode deserialize. Catches codec panics on structurally-valid envelopes. |
| `fuzz_replay_window` | `ReplayWindow::accept()` with adversarial sequence patterns. Catches arithmetic bugs in the window shift / bitmap update. |
| `fuzz_observe_consent` | `Session::observe_consent()` on arbitrary `Vec<ConsentEvent>` (`arbitrary`-derived). Asserts four invariants on every step: no panic; state is always a valid variant; seal-gate matches state per SPEC §12.7; violations never mutate state. |

## Reporting findings

If a target produces a crash, `fuzz/artifacts/<target>/crash-*` is the
reproducer. Please follow the [`SECURITY.md`](../SECURITY.md)
disclosure policy — do not open a public issue with the reproducer.

## Baseline smoke fuzz

`tests/smoke_fuzz.rs` in the main crate is a stable-toolchain smoke
fuzzer that runs ~310,000 random envelopes through `Session::open()` as
a regular `cargo test`. It is the minimum-viable fuzz coverage. The
cargo-fuzz targets here are the follow-on for deeper, coverage-guided
campaigns.
