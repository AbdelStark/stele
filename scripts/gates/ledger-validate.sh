#!/usr/bin/env bash
# RFC-0020 §5 — ledger-validate gate.
set -euo pipefail
exec python3 "$(dirname "$0")/check.py" ledger-validate "$@"
