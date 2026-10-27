#!/usr/bin/env bash
# RFC-0020 §4 — direct float tokens supplement compiler type/arithmetic lints.
set -euo pipefail
exec python3 "$(dirname "$0")/../rust_policy.py" "$@"
