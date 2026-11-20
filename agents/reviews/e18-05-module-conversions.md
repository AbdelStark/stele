# Review Record — `E18-05`: RFC-0028 §1.2 Module Conversions & Accounting Report

- **Task:** `E18-05` (completing module conversions for `E18-02`, `E18-03`, `E18-04`, `E18-05`)
- **Lane:** P (`stele-ir`, `stele-reductions`, `stele-prover`, `tests/negative-controls`, `research/plan-registry`, `bench/ledger`)
- **Governing RFCs:** `RFC-0028 §§1.2, 2.1–2.5, A1`, `RFC-0026 §§3.5a, 5, A15, A16, A26–A28`
- **Tier:** Development tier (`RFC-0027 §2`); no security level or profile promotion claimed.
- **ADR:** `ADR-151` (`agents/context/decision-log.md`)

## 1. Commit-Rule Inventory & Restated Output-Uniqueness Lemmas (RFC-0026 §5, RFC-0028 §1.2)

Every RFC-0026 §5 module header enumerates its committed witness advice columns; no module commits any column definable under RFC-0028 §2.1:

| RFC-0026 §5 Row | Module | Committed Witness Advice | Virtual Columns | Output Uniqueness |
|---|---|---|---|---|
| 1 | `Embedding` (`development/embedding.rs`) | `sigma` (`u1`), plus when `s < 0`: `R0` (`s16`) and optional `rho_hi` (`h > 16`) | `G_b` contractions, `G`, `R0` (`s >= 0`), `rho_lo` (`s < 0`) | Sign lookup fixes `sigma = [G < 0]`; `s >= 0`: `R0 = G*m*mm*w`; `s < 0`: `2^h*R0 - P + sigma + 2^(h-1) - 1 = rho in [0, 2^h)` fixes `R0 = R(P/2^h)` uniquely. |
| 2 | `RmsNorm` (`development/rmsnorm.rs`) | `X1` (`s8`), `H0/H1` (for `X`), `S_pq` row-domain byte limbs, `sigma/Q/R_top/gap_top` carries, `M/M1/J/J1`, radix-12 `Jg/carry*`, `Y` (`s16` or `s24` limbs), radix-12 output carries & pre-multiplied `P_q0/P2` (plus `P_q1/P3` for int24) | `X0`, `S_pq` contractions, `S_*`, `Jg` radix-12 limbs, `Z0..Z_{top-1}` low remainders, `R0..R3`, `gap0..gap3`, `P0..`, `output` (`int24` compose) | Exhaustive mutation survey (`rmsnorm-mutation.txt`, 257 rows) confirms every single dropped constraint is attacked; `P = X*H` in radix-12 (`OUT_RADIX = 12`) preserves exact integer product `X*g*J` under `raw <= HALF_MODULUS` with A1 tightening on ranged limbs. |
| 3 | `RowConversion` (`development/row.rs`) | Compact: `M` (row max), `max/hit`, `scale`, quantized `codes` (`s8`), plus `quotient` & `sign` advice (`RStep`) | `dot`/`max` slack, `remainder`, `half` & rounding residuals | `hit*slack = 0` + `sum_k hit = 1` pins `M`; `codes*scale` signed division with virtual remainder and virtual half-up tie fixes `codes` uniquely; verified by `rejects_code_near_misses`. |
| 4 | `Projection` (`development/projection.rs`) | Unified mixed-radix `MixedPlan` (`radix_lo` + `radix_hi`, unsplit carries `c0..c_{L-1}`, `sign`, rounded output `y`, plus `q0`/`b1` where needed) | `acc` contraction, low limbs, virtual remainders, virtual tie/rounding terms | Static `HALF_MODULUS` bound on every limb equation; `survey_projection_constraints` and `survey_projection_range_widening` pass 100%, including general-path `Grouped(2) l=-1` 16-lane wrap-attack verification. |
| 5 | `Rope` (`rope.rs`) | Rounded outputs `y_even`, `y_odd` (`s16`), `sign` bits, top rounding remainders when shift > 16 | Exact products `x*cos`, `x*sin`, combined sums, low rounding remainders | `2^h * y - exact + sign + 2^(h-1) - 1 = rem in [0, 2^h)` fixes `y_even`, `y_odd` uniquely over `Z`. |
| 6–8 | `Attention` (`development/attention.rs`) | Mixed-radix score advice (`limbs = 1` when `wbits` fits, else `score/w1`, `score/d1`, `score/sign`, `score/c*`), `maximum` + `maximum/hit`, `exp/p` (plus `exp/hi,lo,h,l,c`), radix-16 `value/sum_hi` + `total/sign` + `total/magnitude`, radix-12 `normaliser/byte/1..` & `output/quotient/byte/*` + carries | `dot` contraction, `score`, `u`, `Pm`, `Z`, `value/sum/*` contractions, low bytes, remainders, spares, `output` | `accepts_radix16_total_and_radix12_division_and_rejects_near_misses` plus all 9 `attention::tests` verify exact score, causal max, exp, radix-16 total recombination, and radix-12 division uniqueness. |
| 9 | `GatedProduct` (`silu.rs`, `silu/conversion.rs`) | 3 committed columns (`LOW_BITS = 14`): `up_high` (`s2`), `carry` (`s16`), `activation` (`s16`); plus radix-`2^14` limbs in `GatedConversion` | `up_low` (`u14`), `low` (`u14`, static mag `1,073,709,056 <= HALF_MODULUS`), `high = up_high*a*mask + carry` (unranged, static mag `98,304`) | `up = 2^14 * up_high + up_low`, `up_low * a * mask = 2^14 * carry + low` with `low in [0, 2^14)` fixes `(carry, low)` uniquely; `up * a * mask = 2^14 * high + low` is exact over `Z`. All 22 `silu::` tests pass. |
| 10 | `Residual` (`residual.rs`) | `k = 0`: **0 committed columns**; `k > 0`: rounded output (`out` or `out_lo/out_hi`), `half` (`u1`), `negative` (`u1`), optional stage-1 split advice (`s > 0`) | `output` (`k = 0`), `low`, `twos`, `tie`, stage-1 remainders | Exact add (`k = 0`) or two-stage half-away rounding (`k > 0`) with virtual remainders and tie inequality. |
| 11 | `Argmax` (`argmax.rs`) | **0 committed columns** | `winner_logit` contraction, `margin = winner_logit - logit - below` (`Range` checked) | `margin >= 0` for all real vocabulary entries forces `logit[y] >= logit[v]` for `v >= y` and `logit[y] > logit[v]` for `v < y`, fixing greedy `y` uniquely. |

## 2. E22-01 Static Accounting Report (Before vs After, Exact Gain Widths)

All numbers are produced by `stele-bench accounting` (`bench/ledger/e22-01-static-accounting-*.json` vs `bench/ledger/e18-05-static-accounting-*.json`):

| Rung | Model (`T`) | Cells Before | Cells After | Cell Ratio | Lookups Before | Lookups After | Lookup Ratio |
|---|---|---:|---:|---:|---:|---:|---:|
| `L1` | `eight-layer` (`T=64`) | 15,618,112 (`244,033/tok`) | 8,369,600 (`130,775/tok`) | **1.87x** | 15,027,520 (`234,805/tok`) | 12,534,720 (`195,855/tok`) | **1.20x** |
| `L2a` | `stories42m` (`T=64`) | 216,058,944 (`3,375,921/tok`) | 65,002,624 (`1,015,666/tok`) | **3.32x** | 268,933,440 (`4,202,085/tok`) | 203,484,736 (`3,179,449/tok`) | **1.32x** |
| `L2b` | `stories42m` (`T=1024`) | 5,170,381,824 (`5,049,201/tok`) | 1,387,710,464 (`1,355,186/tok`) | **3.73x** | 4,820,997,120 (`4,708,005/tok`) | 2,818,040,832 (`2,751,993/tok`) | **1.71x** |
| `L3a` | `Llama-3.1-8B` (`T=64`) | 5,331,956,672 (`83,311,823/tok`) | 1,794,575,872 (`28,040,248/tok`) | **2.97x** | 13,815,824,896 (`215,872,264/tok`) | 12,447,998,080 (`194,499,970/tok`) | **1.11x** |
| `L3b` | `Llama-3.1-8B` (`T=1024`) | 119,896,488,960 (`117,086,415/tok`) | 35,452,411,904 (`34,621,496/tok`) | **3.38x** | 119,742,930,944 (`116,936,456/tok`) | 77,693,585,408 (`75,872,642/tok`) | **1.54x** |

Bet B1 (`docs/plan.md` §2) kill criterion (`< 4x` on L2) is recorded in `ADR-151` along with its stated fallback.

## 3. Verification & Negative Controls

- `cargo test -p stele-reductions --lib`: 182/182 passed (including projection constraint/range surveys, 257-row `rmsnorm-mutation.txt` exhaustive attack survey, 22 `silu::` tests, and 9 `attention::` tests).
- `cargo test --release -p stele-prover --test development`: all 24/24 integration tests passed (including `dev-zk` byte-1/byte-4, A15 codecs, A16 published entries & request invariance).
- `cargo test --release -p stele-negative-controls --all-features --lib`: 24/24 passed (including `NC-1310`, `NC-1321..1324`, `NC-1335..1340`, `forged-table`, `forged-public`, and privacy tests).
- `cargo test --release -p stele-negative-controls --all-features --test catalog`: all 8/8 harness tests passed (including `NC-1302..1308`, `NC-1325..1334`, and full executed catalogue coverage).
- `scripts/gates/native.sh`: full union gate including independent `no_std` `stele-verifier` replay of `one-layer`, `eight-layer`, `forged-table`, `forged-public`, `vectors.py --check`, `stele-verifier --test registered`, and `stele-cli --test registered`.
- `scripts/gates/ledger-validate.sh`, `rust-policy.sh`, `glossary-lint.sh`, `rfc-status.sh`, `docs-links.sh`: all passed.

## 4. Independent Soundness Audit

- **Auditor:** Independent `soundness-auditor`
- **Scope audited:** `f69e1333..1038341b` (`stele-ir`, all 10 RFC-0026 §5 proving modules in `stele-reductions`, `stele-prover` v2 routing & `dev-zk` materialization, `tests/negative-controls`, `ADR-151`, `bench/ledger/e18-05-static-accounting-*.json`, `bench/scoreboard.md`, `tests/digests/development.json`).
- **Verdict:** **APPROVED** (0 blocking findings; 3 minor non-blocking nits noted).
- **Summary:**
  1. RFC-0028 A1 tightening in `stele-ir` matches `stele-verifier` (`E18-05a`) verbatim (`raw <= HALF_MODULUS` checked prior to range tightening; `validate_discipline` non-bootstrapping for `Kind::Virtual`).
  2. All 10 converted modules (`embedding`, `rmsnorm` radix-12, `row`, `projection` mixed-radix `PerRow`/`PerRowSplit`/`Grouped2`/`Grouped4` + `TopSplit::{One,Two,Three}`, `rope`, `attention` mixed-radix score + `(c,group,j)` `sv*v` + radix-16 total + radix-12 division, `silu` radix-14 + `silu/conversion`, `residual`, `argmax`) preserve exact integer semantics, output uniqueness over the integers, padding pinning, and static `<= HALF_MODULUS` bounds with no wrap-around loopholes.
  3. `dev-zk` materialization preserves structural invariance between dummy and real weights (privacy intact) and validates materialized relations before assignment.
  4. `prove_segmented_forged` is strictly gated behind `#[cfg(feature = "controls")]`; `verify_segmented` is unchanged; all negative controls remain non-vacuous.
  5. All L1/L2a/L2b/L3a/L3b static accounting numbers in `ADR-151`, `bench/scoreboard.md`, and §2 above match `bench/ledger/e18-05-static-accounting-*.json` verbatim; zero `unsafe`, zero floats, zero Draft RFC refs in `.rs`.
  6. Non-blocking nits addressed: added `*summed > MAX_VARS` defensive guard in `stele-ir::column_magnitude_cached` and updated the `rmsnorm.rs` / Row 2 doc comments (`Es` multiple of `OUT_RADIX = 12`, `S_pq` row-domain byte limbs, virtual `Jg` limbs). The remaining `Chain::declare_virtual` `def_bound` heuristic note is harmless because `Relation::validate()` independently enforces exact static bounds.
