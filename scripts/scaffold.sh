#!/usr/bin/env bash
# Generates the Cargo workspace skeleton from RFC-0020 §1. Idempotent: never overwrites an existing crate.
set -euo pipefail
cd "$(dirname "$0")/.."
# name|rfc|deps(space separated)|unsafe_allowed
CRATES='
stele-field|RFC-0003||no
stele-simd|RFC-0003 §6|stele-field|yes
stele-poly|RFC-0006 §5|stele-field stele-simd|no
stele-hash|RFC-0012|stele-field|no
stele-sumcheck|RFC-0006|stele-poly stele-hash|no
stele-gkr|RFC-0006 A4/A7|stele-field stele-poly stele-hash stele-sumcheck|no
stele-lookup|RFC-0008|stele-gkr|no
stele-code|RFC-0010 §3|stele-field stele-simd|no
stele-pcs|RFC-0010|stele-code stele-field stele-hash stele-poly|no
stele-cqis|RFC-0004|stele-field|no
stele-ir|RFC-0005|stele-cqis|no
stele-reductions|RFC-0007 RFC-0008 RFC-0009 RFC-0017|stele-field stele-hash stele-sumcheck stele-gkr stele-lookup stele-pcs stele-ir|no
stele-proof|RFC-0016 §1|stele-field|no
stele-prover|RFC-0007 §4 RFC-0014 §4|stele-reductions stele-proof|no
stele-verifier|RFC-0016|stele-field stele-hash|no
stele-kernels|RFC-0014 §2|stele-field|no
stele-gpu|RFC-0014|stele-kernels stele-prover|yes
stele-dist|RFC-0015|stele-gpu|no
stele-passport|RFC-0011|stele-pcs stele-cqis stele-wrapper|no
stele-wrapper|RFC-0016 §5|stele-verifier|no
stele-bench|RFC-0018|stele-prover|no
stele-cli|RFC-0020|stele-prover stele-verifier stele-passport stele-bench|no
stele-py|RFC-0020 §1|stele-prover stele-verifier|no
'
echo "$CRATES" | grep -v '^$' | while IFS='|' read -r name rfc deps uns; do
  d="crates/$name"; [ -d "$d" ] && continue
  mkdir -p "$d/src"
  depl=""; for x in $deps; do depl="$depl$x = { path = \"../$x\" }\n"; done
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\nlicense = "Apache-2.0"\ndescription = "Stele — %s (see %s)"\n\n[dependencies]\n%b\n[lints]\nworkspace = true\n' "$name" "$name" "$rfc" "$depl" > "$d/Cargo.toml"
  if [ "$uns" = "yes" ]; then forbid='// unsafe allowed in this crate: every block carries a // SAFETY: comment (agents/guardrails/code.md)'; else forbid='#![forbid(unsafe_code)]'; fi
  case "$name" in
    stele-field|stele-hash|stele-pcs|stele-reductions|stele-proof|stele-verifier) forbid="$forbid
#![no_std]" ;;
  esac
  printf '//! %s — governed by %s. No behaviour exists here that is not specified there (INV-1).\n%s\n#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn skeleton_compiles() {}\n}\n' "$name" "$rfc" "$forbid" > "$d/src/lib.rs"
done
echo "scaffold complete"
