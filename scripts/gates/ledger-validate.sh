#!/usr/bin/env bash
# RFC-0018 §1 — validate every measured ledger; fixtures live outside bench/ledger.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
shopt -s nullglob
ledgers=(bench/ledger/*.json)
if [[ ${#ledgers[@]} -eq 0 ]]; then
  echo 'gate ledger-validate: nothing to check (no measured ledgers)'
  exit 0
fi
cargo run -p stele-bench --locked --offline -- ledger validate "${ledgers[@]}"
