# Independent Soundness Audit — `E18-05a` (`stele-verifier` RFC-0028 v2 + Virtual Columns)

- **Branch / Commit:** `task/E18-05a-verifier-virtual-columns` (`5bc401e5..3bb7d38d`, audited on identical diff `c0c848ea..4c48e4fe`)
- **Lane / Role:** Lane V — Independent `soundness-auditor` (Workflow 03, ADR-128)
- **Verdict:** **APPROVED** (zero blocking findings)

## Scope Audited
- `docs/rfcs/RFC-0028-relation-ir-v2.md` (§2.2 A1 range-tightened downstream magnitude, §2.5 canonical v2 wire and `reductions` specification)
- `crates/stele-verifier/src/{relation,plan,development,registered}.rs`
- `crates/stele-verifier/tests/development_replay.rs`
- `research/plan-registry/vectors.py`, `scripts/gates/check.py` (5 SHA-256 `stele-verifier` pins verified exact)

## Findings Summary
1. **Wire, Transcript & ID Parity (INV-1, INV-2):** `stele/v0.1/relation/encoding/v2`, `stele-dev-e2e-v2` (`ContainerV2`), `SegmentedPlan`, RFC-0026 A28 virtual lookup member absorption (`AbsorbLabel::Final` with `check_id: u64le || [(m_idx: u32le || slot: u8 || val: 16B)]`, no-op when no virtual member), and Step 2.4 `Linear`/`Contraction`/`Pointwise` virtual reduction replay match RFC-0026 A26/A27/A28 and RFC-0028 §§2.1–2.5 byte-for-byte with disjoint instance IDs and exact section-count and byte-length verification.
2. **Static Field Faithfulness & A1 Soundness (INV-5):** `Relation::validate` checks `raw <= HALF_MODULUS` before applying A1 `Range` tightening (`raw.min(range.width.mag())`), ensuring over-wide virtual definitions reject (`NC-1340`) and statically wrap-free ranged virtual columns satisfy `HALF_MODULUS + 65535 < p` over the integers. In `discipline(&mags)`, `Range`/`Lookup`/`Compose`/`Matmul` never mark `Kind::Virtual` as `enforced`; a virtual column becomes `enforced` solely after all earlier (`op < id`) operands are `enforced`, eliminating cyclic bootstrapping by strong induction.
3. **Registry Normalization (`registered.rs`, `vectors.py`):** v2 group segments, virtual definitions, and `carried` flags are skipped identically and hashed unmodified into the trusted template digest; reserved request columns still require `Kind::Public`, blocking tag-`3` substitution (`RegistryRequestMismatch`).
4. **Independence & Hygiene (INV-11, INV-12):** Zero prover dependency (`stele-field` and `stele-hash` only), `#![forbid(unsafe_code)]`, `#![no_std]`, zero floats, and zero `unwrap`/`expect` in library code.

## Non-Blocking Notes
1. `crates/stele-verifier/src/relation.rs`: `let mut ops = Vec::new(); def.for_each_operand(|op| ops.push(op));` is already bounded by fallibly decoded terms/factors and can be made zero-allocation in a future cleanup.
2. Scope note: `Public::decode` remains pinned to `stele-dev-public-v4` (RFC-0026 A15 §2), covering all v1 proofs and unsegmented virtual-column `stele-dev-e2e-v2` proofs (`E18-05`); multi-segment `stele-dev-public-v5` bundles fail closed (`StatementMismatch`) until a dedicated Lane-V A27 public-bundle task adds `v5` decoding.

## Evidence Verified
- `cargo check -p stele-verifier --no-default-features`
- `cargo clippy -p stele-verifier --all-targets -- -D warnings`
- `cargo test -p stele-verifier` (45/45 unit + integration)
- `development_replay` against genuine `E18-05` v2 windows (`one-layer`, `eight-layer`, `forged-table` -> `TableDenominatorMismatch`, `forged-public` -> `PublicMismatch`, plus all one-byte, shape, and semantic tamper regressions)
- `scripts/gates/{rust-policy,glossary-lint,rfc-status,docs-links}.sh` and `python3 scripts/ci_tests.py`
