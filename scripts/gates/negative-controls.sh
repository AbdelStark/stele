#!/usr/bin/env bash
# RFC-0002 §7 / RFC-0020 §5 — run controls before reporting coverage.
set -euo pipefail
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--coverage" ) ]]; then
  echo "usage: $0 [--coverage]" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/../.." && pwd)"
python3 "$root/scripts/gates/check.py" negative-controls
cd "$root"
cargo test -p stele-negative-controls --locked --offline
cargo run -p stele-negative-controls --bin stele-controls --locked --offline -- --coverage
