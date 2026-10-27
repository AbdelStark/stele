#!/usr/bin/env bash
# RFC-0020 §5 — docs-links gate.
set -euo pipefail
exec python3 "$(dirname "$0")/check.py" docs-links "$@"
