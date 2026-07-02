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

for required_file in plans/FULL_PQC_BOUNDARY.md SECURITY.md; do
  if [[ ! -f "$required_file" ]]; then
    fail "missing xenia-wire PQC boundary file: $required_file"
  fi
done

if ! grep -q "Adjacent real-backend note" plans/FULL_PQC_BOUNDARY.md; then
  fail "missing adjacent real-backend boundary note"
fi
if ! grep -q "must keep its claim" SECURITY.md; then
  fail "missing wire crate claim-boundary note"
fi

if (( failures > 0 )); then
  echo "xenia-wire PQC boundary check failed with $failures failure(s)" >&2
  exit 1
fi

printf 'xenia-wire PQC boundary check passed\n'
