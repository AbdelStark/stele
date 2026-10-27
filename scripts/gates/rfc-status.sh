#!/usr/bin/env bash
# RFC-0020 §5 — rfc-status gate.
set -euo pipefail
exec python3 "$(dirname "$0")/check.py" rfc-status "$@"
