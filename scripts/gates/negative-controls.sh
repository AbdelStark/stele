#!/usr/bin/env bash
# RFC-0020 §5 — negative-controls gate.
set -euo pipefail
exec python3 "$(dirname "$0")/check.py" negative-controls "$@"
