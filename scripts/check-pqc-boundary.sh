#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
run_required() {
  local path="$1"
  shift
  if [[ ! -x "$path" ]]; then
    fail "missing executable xenia-wire PQC boundary check: $path"
    return
  fi
  echo "+ $path $*"
  if ! "$path" "$@"; then
    fail "command failed: $path $*"
  fi
}

run_required scripts/check-pqc-claims.sh .
run_required scripts/check-pqc-claim-guard-negative.sh .

for required_file in \
  plans/FULL_PQC_BOUNDARY.md \
  SECURITY.md \
  Cargo.toml \
  src/lib.rs; do
  if [[ ! -f "$required_file" ]]; then
    fail "missing xenia-wire PQC boundary file: $required_file"
  fi
done

if ! grep -q "Adjacent real-backend note" plans/FULL_PQC_BOUNDARY.md; then
  fail "missing adjacent real-backend boundary note"
fi

# The current architecture has an optional handshake feature. The guard must
# enforce that fact without promoting the whole crate into a complete PQ product.
if ! grep -q '^handshake = \[' Cargo.toml; then
  fail "Cargo.toml no longer declares the optional handshake feature"
fi
if ! grep -Fq 'pub mod handshake;' src/lib.rs; then
  fail "src/lib.rs no longer exports the handshake module under its feature"
fi
if ! grep -Fq 'pub mod handshake_highsec;' src/lib.rs; then
  fail "src/lib.rs no longer exports the high-security handshake module"
fi
if ! grep -Fq 'optional `handshake` feature' SECURITY.md; then
  fail "SECURITY.md does not describe the optional handshake boundary"
fi
if ! grep -Fq 'not as a standalone post-quantum product-security layer' SECURITY.md; then
  fail "SECURITY.md is missing the standalone-product non-claim"
fi

# Reject stale boundary language that became false once optional handshake and
# consent-state implementations were added to this crate.
if grep -Fq '`xenia-wire` does not perform key establishment or peer authentication' SECURITY.md; then
  fail "SECURITY.md still claims xenia-wire has no key-establishment/authentication surface"
fi
if grep -Fq 'handshake layer (not yet published)' SECURITY.md; then
  fail "SECURITY.md still describes the in-repo handshake as unpublished"
fi
if grep -Fq '**No handshake.**' src/lib.rs; then
  fail "crate docs still claim there is no handshake surface"
fi
if grep -Fq '**No state machine.**' src/lib.rs; then
  fail "crate docs still claim there is no state-machine surface"
fi

if (( failures > 0 )); then
  echo "xenia-wire PQC boundary check failed with $failures failure(s)" >&2
  exit 1
fi

printf 'xenia-wire PQC boundary check passed\n'
