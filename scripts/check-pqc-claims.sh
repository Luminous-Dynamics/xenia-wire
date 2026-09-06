#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
cd "$root"

patterns=(
  "PQC-sealed binary wire protocol"
  "entirely PQC"
  "entirely post-quantum"
  "fully PQC"
  "full PQC"
  "full-PQC"
  "full post-quantum"
  "fully post-quantum"
  "PQC at every layer"
  "quantum-safe wire"
  "quantum-secure wire"
)

allow_re='(^|/)(plans/FULL_PQC_BOUNDARY\.md|scripts/check-pqc-claims\.sh|scripts/check-pqc-claim-guard-negative\.sh)$'
failures=0

for pattern in "${patterns[@]}"; do
  while IFS=: read -r file line text; do
    [[ -z "${file:-}" ]] && continue
    if [[ "$file" =~ $allow_re ]]; then
      continue
    fi
    printf 'PQC claim overreach: %s:%s: %s\n' "$file" "$line" "$text" >&2
    failures=$((failures + 1))
  done < <(grep -RIni --exclude-dir=.git --exclude-dir=target --exclude='*.patch' -- "$pattern" . || true)
done

if (( failures > 0 )); then
  cat >&2 <<'MSG'

Strong PQC wording found in xenia-wire. The core/default wire surface remains
AEAD/replay/consent oriented, while optional pre-alpha handshake modules provide
specific ML-KEM/ML-DSA protocol compositions. Neither fact establishes that the
crate or any Xenia product is a complete, independently audited quantum-safe
system. Keep product-level PQ claims tied to separate evidence.
MSG
  exit 1
fi

printf 'xenia-wire PQC claim check passed\n'
