#!/usr/bin/env bash
# RFC-0020 §5: digest, controls and accounting without repeated validators.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
python3 "$root/scripts/gates/check.py" native
cd "$root"
cargo test -p stele-negative-controls --locked --offline
cargo run -p stele-negative-controls --bin stele-controls --locked --offline -- --coverage
