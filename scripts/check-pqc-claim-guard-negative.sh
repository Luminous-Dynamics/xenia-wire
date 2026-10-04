#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
repo_script="$root/scripts/check-pqc-claims.sh"

if [[ ! -x "$repo_script" ]]; then
  echo "missing executable PQC claim guard: $repo_script" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

allowed="$tmp/allowed"
mkdir -p "$allowed"
cat >"$allowed/README.md" <<'EOF'
# Allowed precise wire wording fixture

xenia-wire's core sealing API provides AEAD framing and replay protection, and
optional pre-alpha modules add consent and specific ML-KEM/ML-DSA handshake
compositions. Those features do not establish that xenia-wire or any Xenia
product is a complete or independently audited post-quantum security system.
EOF

allowed_log="$tmp/allowed.log"
if ! "$repo_script" "$allowed" >"$allowed_log" 2>&1; then
  cat "$allowed_log" >&2
  echo "xenia-wire PQC claim guard rejected precise non-overclaim wording" >&2
  exit 1
fi

claims=(
  "PQC-sealed binary wire protocol"
  "ENTIRELY PQC"
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

for index in "${!claims[@]}"; do
  claim="${claims[$index]}"
  fixture="$tmp/negative-$index"
  mkdir -p "$fixture"
  cat >"$fixture/README.md" <<EOF
# Negative wire PQC claim fixture

This intentional overclaim must be rejected: xenia-wire is a ${claim} today.
EOF

  log="$fixture/claim-guard.log"
  if "$repo_script" "$fixture" >"$log" 2>&1; then
    cat "$log" >&2
    echo "xenia-wire PQC claim guard accepted intentional overclaim: $claim" >&2
    exit 1
  fi

  if ! grep -q "PQC claim overreach" "$log"; then
    cat "$log" >&2
    echo "xenia-wire PQC claim guard failed without reporting overclaim: $claim" >&2
    exit 1
  fi
done

printf 'xenia-wire PQC claim guard negative check passed (%s cases)\n' "${#claims[@]}"
