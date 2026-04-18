# Contributing to xenia-wire

Thanks for your interest. `xenia-wire` is in pre-alpha, which means
the best contributions right now are design feedback, not code.

## If you've found a problem

- **Security issue**: please follow [`SECURITY.md`](SECURITY.md) —
  do not open a public issue.
- **Bug / incorrect behavior**: open a GitHub issue with a minimal
  reproducer.
- **Spec question or design concern**: open a GitHub issue or
  Discussion. We especially want review feedback on the nonce
  layout, replay window semantics, and the key-rotation grace
  period.

## If you want to send a pull request

Small fixes (typos, obvious bugs, doc clarifications) are welcome
via PR without prior discussion. For anything larger — new API
surface, behavior changes, or anything touching the wire format —
please open an issue first so we can agree on scope before you
invest the time.

### Local development

```console
$ cargo test                         # default features
$ cargo test --all-features          # + lz4
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo fmt --check
$ cargo doc --all-features --no-deps
```

### Property tests

`tests/proptest_wire.rs` exercises the core invariants across
thousands of randomized inputs. New wire-format changes should
come with a property test that captures the invariant.

### Commit style

Conventional-commit-ish is preferred but not enforced:

- `feat: add ConsentRequest payload type`
- `fix: reject envelopes shorter than nonce + tag`
- `docs: document the LZ4-before-seal rule`
- `test: add replay-window edge-case property`

## License

By contributing, you agree that your contributions will be
dual-licensed under the Apache-2.0 AND MIT licenses (matching
the crate's overall licensing). You do not need to sign a CLA.

## Code of conduct

Be kind, be specific, be correct. Disagreement about protocol
design is expected and welcome; personal attacks are not.
