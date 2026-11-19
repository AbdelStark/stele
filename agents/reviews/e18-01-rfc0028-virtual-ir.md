# Independent Review — E18-01: RFC-0028 acceptance (development tier), virtual column types, validation, and plain checker

- **Task:** `E18-01` (Lane P, `stele-ir` + companion RFC amendments + `stele-reductions` staging)
- **Reviewer:** Independent `soundness-auditor` and cross-lane reviewer (`Lane N/V`)
- **Tier:** Development tier (RFC-0027 §2); no security level or profile promotion granted
- **Verdict:** **APPROVE** (after resolving findings F1–F6)

## Findings Resolved

1. **F1 (Blocker — resolved):** Replaced unmemoized recursion in `Relation::column_segment` with an iterative `O(columns + operands)` forward pass `Relation::column_segments(&self) -> Vec<Option<u32>>`, reused across `weight_segments`, `validate`, `validate_item_segment`, `*_segment_with`, `range_segment_with_segs`, and `check_inner`. Verified with a depth-64 diamond virtual DAG regression test.
2. **F2 (Blocker — resolved):** Replaced `v.checked_shl(u32::from(shift))?` with `v.checked_mul(1i128 << shift)?` in `crates/stele-ir/src/relation/check.rs` Compose evaluation so `i128` overflow on virtual limbs cannot silently wrap. Verified with a `check_segment` regression test using a tampered carried column (`(1 << 40)^3 << 8`).
3. **F3 (Blocker — resolved):** Added explicit refusal `if relation.has_virtual() || relation.is_segmented() { return Err(Error::Statement); }` in `crates/stele-reductions/src/zk_relation.rs::layout` immediately after `relation.validate()`, preventing an `unreachable!` panic on validated virtual relations.
4. **F4 (Minor — resolved):** Rejected `column.segment.is_some()` whenever `op_max.is_some()` in `Relation::validate()`, aligning strictly with RFC-0028 §2.3, RFC-0026 A28 item 3, and `Column.segment`'s doc comment.
5. **F5 (Minor — resolved):** Added unit tests covering `i64::MIN` constant/coeff (`Invalid::Bound`, no panic), split `Def::Contraction` (`free = 20, summed = 15`), `check_with(..., summed_table = 0)` on `Def::Contraction`, `verify` / `verify_segmented` returning `Err(Error::Unsupported)`, and v1/v2 `relation_codec::encode` prefixes.
6. **F6 (Nit — resolved):** Updated downstream `agents/tasks/graph.yaml` NC references (`E18-02`: `NC-1337..1338`, `E18-04`: `NC-1339..1340`) and tightened the `a15_relation` test helper assertion in `crates/stele-prover/tests/development.rs`.

## Verification

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`
- `cargo test -p stele-ir --all-features --locked --offline` (35/35 pass)
- `cargo test -p stele-ir --no-default-features --locked --offline` (35/35 pass)
- `cargo test -p stele-reductions --lib --locked --offline rejects_virtual_columns_until_e18_02_and_encodes_distinctly` (pass)
- `cargo test -p stele-negative-controls --all-features --test catalog --locked --offline accepts_repository_catalog_without_crediting_stub` (152/252 executed controls pass; `NC-1337..1340` reserved `todo`)
- `scripts/gates/rfc-status.sh`, `scripts/gates/docs-links.sh`, `scripts/gates/glossary-lint.sh`, `scripts/gates/rust-policy.sh` (all pass)

## Workflow 03 Adversarial Statement

Attempted to break `E18-01` via forward and self virtual column references, `HALF_MODULUS + 1` and `NC-1340` field-inverse derived magnitudes, `i64::MIN` constants/coefficients, zero-magnitude virtual columns, cyclic witness self-disciplining through `Range`/`Lookup`/`Compose`/`Matmul` over virtual wrappers, cross-segment virtual and non-carried witness reads, explicit `Column.segment` overrides on operand-bearing virtuals, v1/v2 `relation_codec::encode` ambiguity collisions, depth-64 diamond virtual DAG validation DoS, `i128` shift overflow wrapping in `Compose` under `check_segment`, and passing validated virtual/segmented relations into `stele-reductions` (`relation::plan`, `plan_segmented`, and `zk::relation::layout`). Every attack is rejected cleanly and deterministically, with unsegmented v1 and segmented-without-virtual v2 encodings preserved byte-identically and no security level or profile promotion claimed.
