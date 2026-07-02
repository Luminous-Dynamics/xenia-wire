#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

patterns=(
  "PQC-sealed binary wire protocol"
  "entirely PQC"
  "entirely post-quantum"
  "fully PQC"
  "PQC at every layer"
)

allow_re='(^|/)(plans/FULL_PQC_BOUNDARY\.md|scripts/check-pqc-claims\.sh)$'
failures=0

for pattern in "${patterns[@]}"; do
  while IFS=: read -r file line text; do
    [[ -z "${file:-}" ]] && continue
    if [[ "$file" =~ $allow_re ]]; then
      continue
    fi
    printf 'PQC claim overreach: %s:%s: %s\n' "$file" "$line" "$text" >&2
    failures=$((failures + 1))
  done < <(grep -RIn --exclude-dir=.git --exclude-dir=target --exclude='*.patch' -- "$pattern" . || true)
done

if (( failures > 0 )); then
  cat >&2 <<'MSG'

Strong PQC wording found in xenia-wire. This crate is AEAD/replay/consent wire
format only; PQ key establishment and PQ authentication live above it.
MSG
  exit 1
fi

printf 'xenia-wire PQC claim check passed\n'
