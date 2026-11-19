# Independent Lane P Review — Task E22-03 & RFC-0026 A25

- **Task:** `E22-03` (Lane N — Wide residual and Llama-3.1-8B configuration in proving modules)
- **Amendment:** RFC-0026 A25 (development-tier amendment under RFC-0027 §2, Workflow 02 item 4)
- **Reviewer:** Independent Lane P reviewer (`579592cd-cb4b-4575-9afd-14362e75ea4a`)
- **Verdict:** **APPROVE** (after resolving F1–F4)

## Findings & Resolution

1. **F1 [Medium — Resolved]:** A25's initial `Soundness` paragraph cited non-existent §6 ledger line labels (`ZC`, `M`) and omitted per-round enumeration. Fixed in `docs/rfcs/RFC-0026-development-end-to-end.md` to cite the exact §6 ledger lines (`RLC`, `SC`, `SZ`, `LU`, `PCS`, `H`, `FS`) and enumerate all added and shifted rounds and error terms for grouped gated `Projection`, wide `Projection`/`Residual`, grouped `GatedConversion`, and GQA.
2. **F2 [Low — Resolved]:** Clarified the §1.3 replacement header to name `(first two bullets, fourth bullet, and an added bullet)`.
3. **F3 [Low — Resolved]:** Added explicit rejection tests for `Finish::new` with `head.output_bits = 24` and `8` (`crates/stele-reductions/src/finish/tests.rs`), direct `Projection::new` rejection tests for unsupported `output_bits` (`crates/stele-reductions/src/development/tests.rs`), and restamped `statement_digest_for(&public, &bad)` engine-rejection assertion on `one-layer-wide-gqa` (`crates/stele-prover/tests/development.rs`).
4. **F4 [Info — Resolved]:** Updated stale `Projection::output` doc comment (`signed 16 or signed 24`).

## Verification Summary

- **`GatedConversion` (`Policy::Grouped(g)`):** Verified power-of-two/divisor validation, group-domain broadcast refs, `attained/one-hot` matmul indices, padded-group pinning when `hidden` is non-power-of-two (e.g., `14336`), and `Policy::Dynamic` byte-identity.
- **`Projection` (`wide_grouped` and `output_bits = 24`):** Verified `fold/scale` and radix-256 `fold` chain eliminate RFC-0004 A15's `X - p` alias over Z, balanced signed-8 digits keep matmul sums within `signed(30)` up to `inner = 16384` (worst identity bound `1,631,650,300 < p`), 3-byte `Compose` disciplines `magnitude` (`u24`) and `output` (`i24`), and `Finish::build` rejects `head.output_bits != 16`.
- **`Residual::new_wide` (`bits = 24`):** Verified exhaustively across all `31^3 = 29,791` fraction triples (`bound <= 1,619,001,471 < p`), exact `narrow` coverage (zero false rejections of non-overflowing inputs), `twos` handling at `out = -2^23, half = 1`, int16 `R_0` left input compatibility, and version-1 byte-identity.
- **`Layout::declare` & fixtures:** Confirmed only the five RFC-0004 A14 value classes are wide int24; GQA non-power-of-two `heads / groups` rejected by `Attention::new`; existing `one-layer`, `one-layer-grouped`, and `eight-layer` bytes and pinned FNV digests unchanged.
- **Sign-off:** RFC-0026 A25 is Accepted at the development tier under RFC-0027 §2 / Workflow 02 item 4. Promotion to `standard` or `treaty` is not granted (Workflow 10).

## Addendum — Row 6 Tightened `score/scales` (RFC-0026 A25)

- **Reviewer:** Independent Lane P reviewer (`4cf97a40-12a0-4c77-bfb4-c650ef008387`)
- **Verdict:** **APPROVE** (after resolving A1–A3)

### Findings & Resolution

1. **A1 [Medium — Resolved]:** Added Row 6 soundness-accounting bullet to RFC-0026 A25 `Soundness` (`score/scales/2` moving from `range_2` to `range_1`, narrower `score/quotient`/`maximum/hi`/`score/round` carry `LU` checks, and byte-boundary limb/identity reduction on mixed static/dynamic policies), plus Llama-3.1-8B G7 attention validation and Row 6 controls in `Controls`.
2. **A2 [Low — Resolved]:** Tightened A25 Row 6 wording to name `S_max = Q_max · 2^max(e, 0) >= 2^28` at `W_max = 2^wbits - 1`, `s <= scale_bound`, and static enforcement via ranged `score/scales` limbs plus wrap-free radix-256 chain.
3. **A3 [Low — Resolved]:** Added explicit `score/scales/2` `Width::unsigned(1)` check, `sq = sk = 511` (`W = 261,121`) `Violation::Range` control targeting `L0/attention/score/scales/2/range`, and `dh = 256` `Attention::new` rejection check in `crates/stele-reductions/src/development/attention/tests.rs`.

### Verification Summary

- Verified INV-5 static soundness for `wbits = 17` vs `smax = 511`: `score/scales` chain bounds (`523,520`, `3,327`, `9 << p`) telescope over **Z** and `range_1` on `score/scales/2` statically rules out `W >= 2^17`; Llama-3.1-8B G7 `score_qmax(17) = 189,811,288 < 2^28` keeps `exp/difference` at `1,073,774,589 < p`.
- Verified completeness for all dynamic (`s <= 259`) and static (`s <= scale_bound`) `RowConversion` inputs, `new`/`declare` consistency across all four Static/Dynamic combinations (`loose(Some) ∈ {tight, loose(None)}`), `checked_shl` overflow safety, and strict pre-A25 byte-identity for all models with `score_qmax(loose) < 2^28`.
