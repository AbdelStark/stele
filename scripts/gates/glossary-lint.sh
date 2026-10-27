#!/usr/bin/env bash
# RFC-0020 §4 — glossary policy from the repository root, independent of cwd.
set -euo pipefail
exec python3 "$(dirname "$0")/../glossary_lint.py" "$@"
