# Experiment — Q36, Q38: shift-only rows and weights on Llama-3.1-8B (task E22-02)

Pre-registered by the commit that adds this file, before any score was seen. The screen
is `harness/eval/screen_rows.py` at that commit.

## Why

A projection output costs 21 to 32 lookup positions today. Of the 203,484,736 lookup
positions of L2a, 134,465,792 are range checks of witness columns and 67,108,864 are range
checks of the weights (`bench/ledger/e18-05-static-accounting-l2a.json`). The machinery
behind the first group is named in RFC-0026 §5: the attained maximum of each group of 128
features, the division by the row scale `s = ceil(M/127)`, the digit rows of grouped
scales (RFC-0004 A15), and the wide scaled product `A·m_j·s`. On Llama-3.1-8B at 64 tokens
the witness stage (weight decode, the reference executor and the per-layer assignment of
those columns) takes 293 s of a 1,017 s proof (probe job 7642 on the Lucid reference node,
128 threads, no ledger).

All of it goes away when every scale is a power of two. A conversion is then
`q = R(x / 2^a)`, a projection is `Y = R(A / 2^k)` with `A = Σ q·w` a single matmul on
small codes, and each rounding is one remainder range check.

## Hypothesis

With int8 weights at a power-of-two scale per output row, there is a row format with
power-of-two scales, at most 12-bit codes (10 for the input of `down`) and no attained
maximum per group, whose perplexity is within 0.25% of the grouped dynamic int8 rows of
the G7 configuration (RFC-0004 A15, `g = 128`), in simulation, on every input site.

## Candidates

Input sites: `attn` (the first norm's output, read by Q, K and V), `out` (the attention
output, read by O), `mlp` (the second norm's output, read by gate and up), `down` (the
gated product) and `head` (the final norm's output).

| Format | Scale | Machinery it removes, against grouped dynamic rows |
|---|---|---|
| `dyng128` (baseline) | attained maximum of each group of 128 features, over 127 | none |
| `dynrow` | attained maximum of the row over the code maximum | the digit rows of grouped scales |
| `p2row` | the least power of two at or above `dynrow`'s scale | also the division by a variable scale and the wide scaled product; keeps one attained maximum per row |
| `static` | one calibrated power of two per tensor; codes saturate | also the attained maximum |
| `staticch` | one calibrated power of two per input feature, folded into the weight columns; codes saturate | the same as `static` |

Code widths 8, 10, 12 and 16 bits. With int8 weights a single matmul keeps `|A| < 2^30`
up to 12-bit codes at an input width of 4,096 and 10-bit codes at 14,336 (`down`); a
16-bit code needs two limb matmuls and is measured only to show where the gain saturates.

Weights: `w8`, int8 codes at `absmax/127` per output row (the G7 format), and `w8p2`, the
same codes at the least power of two at or above that scale.

Calibration for the static formats: attained maxima per input feature over the first
four 4,096-token windows of the WikiText-2 raw train split, which shares no text with the
scored windows.

## Model and revision

`meta-llama/Llama-3.1-8B-Instruct`, the model of rung L3 (ADR-149), in float32 from the
safetensors snapshot on the Lucid reference node. The run records the SHA-256 of each
shard.

## Protocol and subset (Workflow 11)

`harness/eval/fidelity.py`: WikiText-2 raw test, non-overlapping 4,096-token windows. The
screen scores the first 8 windows (32,760 tokens), the fixed subset of the earlier sweeps.
Per candidate it records perplexity, its relative change `Δ` against float32 on the same
windows, the per-window negative log-likelihood, and top-1 agreement with float32.

- Stage A, weights alone: `w8`, `w8p2`.
- Stage B, one site at a time with float32 weights and the other sites in float32: 5 sites
  × 5 formats × 4 widths, 100 runs.
- Stage C, every site together: the simulated baseline `w8` with `dyng128` at 8 bits; the
  same with `w8p2`; `w8p2` with each of `static`, `staticch` and `p2row` at 8, 10 and 12
  bits on every site (10 at most on `down`); and the mixed candidate of the decision rule.

This is a float32 simulation. It quantises Linear inputs and weights only: norms, tables,
the residual stream and the embedding are exact. It ranks candidates and attributes the
gap by site. No number of it enters a report as CQIS fidelity.

## Measurements

Fidelity as above. Proof cost per candidate is an estimate until modules exist and the
accounting tool (task E22-01) can count them:

| Format | Lookup positions per input element | Per projection output |
|---|---|---|
| `dyng128` at 8 bits (measured, L2a) | about 10 | 21 to 32 |
| `p2row` | 3 to 4: the code, the remainder at a width the row fixes, the attained-maximum difference | 2 to 3: the output and its remainder at a width the row fixes |
| `static`, `staticch` | 2: the code and the remainder | 2: the output and its remainder |

A code above the single-matmul width adds one lookup position per input element and one
matmul.

## Decision rule and kill criterion

- A format passes on a site when its stage B `Δ` is at most that site's `dyng128` 8-bit
  `Δ` plus 0.05% of the float32 perplexity.
- The mixed candidate takes, per site, the first passing format in this order: `static`
  at 8, 10, 12 bits; `staticch` at 8, 10, 12; `p2row` at 8, 10, 12 (never above the
  site's single-matmul width). A site where none passes keeps `dyng128` at 8 bits.
- A stage C candidate passes the screen when its `Δ` is at most the simulated baseline's
  plus 0.25%. The cheapest passing candidate is recommended for the exact executor
  (task E22-05), where the full G7 protocol decides.
- Kill (bet B4, `docs/plan.md` §2): if no stage C candidate with `w8p2` and a
  power-of-two row format on every site is within 0.5% of the simulated baseline, the
  static-scale direction is dropped for the sites that fail, they keep grouped dynamic
  rows, and the effort goes to a cheaper attained-maximum argument (Q43).

## Budget

One H100 on the Lucid cluster, at most 3 GPU-hours for the three stages. No cloud spend.

## Results of stages A, B and C

Run at the pre-registration commit `38c5792d` on one H100 of the Lucid reference node
(jobs 7647 and 7659). 115 scores in `scores.jsonl`, SHA-256
`1eb34a380c49b7a31c1ed10ff132f3d69f4e08c13cd9fcae7125e8bf706c02cb`. Float32 perplexity on
the 8 windows (32,760 tokens): 6.9155. `Δ` is the relative perplexity change against
float32, in percent. With 8 windows the paired standard error of a difference between two
combined candidates is 0.08 to 0.12 percentage points, so the screen ranks; it does not
resolve differences below that.

Stage A, weights alone: `w8` −0.003, `w8p2` +0.232 (top-1 agreement 98.3% and 97.6%).

Stage B, one site at a time, float32 weights, `Δ` at 8, 10, 12 and 16 bits:

| Site | `dynrow` | `dyng128` | `p2row` | `static` | `staticch` |
|---|---|---|---|---|---|
| `attn` | +0.648, −0.008, −0.000, +0.000 | +0.127, +0.007, +0.000, −0.000 | +0.907, −0.069, +0.008, −0.001 | +2.479, +0.676, +0.038, +0.001 | +0.140, +0.012, +0.005, +0.000 |
| `out` | +0.044, −0.005, +0.000, +0.000 | +0.008, +0.000, −0.000, −0.000 | +0.042, +0.003, +0.001, −0.000 | +0.521, +0.059, −0.009, −0.005 | +0.161, +0.122, +0.115, +0.116 |
| `mlp` | −0.062, +0.009, −0.000, −0.000 | +0.038, +0.002, −0.001, +0.000 | +0.004, −0.003, +0.000, +0.000 | +1.497, +0.056, +0.019, +0.000 | +0.053, +0.001, +0.001, +0.001 |
| `down` | +0.947, −0.027, +0.011, −0.005 | +0.032, +0.014, +0.004, +0.000 | +1.621, +0.143, +0.011, +0.003 | +3064, +275, +35.7, +0.235 | +9.02, +8.97, +8.67, +8.64 |
| `head` | +0.065, +0.004, +0.001, +0.000 | +0.004, +0.002, +0.000, −0.000 | +0.125, +0.008, +0.001, −0.000 | +0.343, +0.021, +0.008, +0.000 | +0.014, +0.005, +0.001, +0.001 |

Stage C, every site together:

| Candidate | `Δ` | Against the simulated baseline | Top-1 agreement |
|---|---|---|---|
| `w8`, `dyng128` at 8 bits (simulated baseline) | +0.194 | — | 97.63% |
| `w8p2`, `dyng128` at 8 bits | +0.435 | +0.241 | 97.33% |
| `w8p2`, `p2row` at 10 bits | +0.352 | +0.158 | 96.92% |
| `w8p2`, `p2row` at 12 bits (10 on `down`) | +0.393 | +0.199 | 97.08% |
| `w8p2`, `p2row` at 8 bits | +2.824 | +2.630 | 91.88% |
| `w8p2`, mixed by the rule: `static` 12 on `attn` and `out`, 10 on `mlp` and `head`, `dyng128` 8 on `down` | +0.491 | +0.297 | 96.77% |
| `w8p2`, `staticch` at 8, 10, 12 bits | +19.96, +18.96, +18.86 | | 80.6% to 81.0% |
| `w8p2`, `static` at 8, 10, 12 bits | +3194, +290, +273 | | 23.8% to 52.2% |

Reading, by the pre-registered rule:

- **The screen passes two candidates**: power-of-two weights with a power-of-two row scale
  at 10 bits on every site (+0.158 over the simulated baseline, limit +0.25), and the same
  at 12 bits. The kill criterion is not met.
- **The mixed candidate fails** (+0.297). Its sites pass one by one, and the sum of their
  single-site costs with the weights' is above the limit.
- **Power-of-two weight scales are most of the gap**: +0.232 alone, +0.241 on top of the
  baseline's rows. A wider code or a short mantissa is the first thing to try.
- **A 10-bit code at a row scale beats grouped int8** on `attn` (−0.069 against +0.127)
  and on `mlp`; on `down` grouped int8 is still better than a 10-bit row scale (+0.032
  against +0.143) and equal at 12 bits.
- **A static scale per feature matches grouped dynamic rows on the norm-fed sites** at
  8 bits: `attn` +0.140 against +0.127, `mlp` +0.053 against +0.038, `head` +0.014
  against +0.004. It is the cheapest format to prove.

Defects the sweep found in its own candidates:

- `staticch` on `out` and on `down` does not improve with the width (+0.115 and +8.6 at
  16 bits): the scored windows exceed the calibrated maxima and the codes saturate. A
  CQIS static row rejects such a row. The screen did not count saturated elements.
- `static` on `down` is unusable at any width up to 12 bits: the gated product is
  heavy-tailed and one scale per tensor leaves the typical element no bits.
- The first job died on stage B when the cluster home passed its quota. Scores are
  appended one by one and the second job resumed after the last one; no candidate was
  scored twice.

## Addendum, pre-registered before its scores

Written with every score above seen, and committed before any score below exists. The
code is `screen_rows.py` at this commit (stages `A2`, `B2`, `C2`).

- **A2, weights alone.** `w9p2` and `w10p2`: 9-bit and 10-bit codes at a power-of-two
  scale per output row. `w8m1`, `w8m2`, `w8m3`: int8 codes at a scale with a 1, 2 or
  3-bit mantissa, the least value `(2^K + i)·2^e` at or above `absmax/127`. A wider
  weight narrows the single-matmul code: 11 bits at an input width of 4,096 and 9 at
  14,336 for 9-bit weights; a `K`-bit mantissa costs `K` bits of it.
- **B2, one site at a time.** The static formats at 8, 10 and 12 bits again with the
  saturated elements counted (suffix `@sat`); `static`, `staticch` and `p2row` at 7, 9
  and 11 bits; `staticch` with one and two bits of room above the calibrated scale
  (`staticchh1`, `staticchh2`) at 8, 9 and 10 bits.
- **C2, every site together**, 17 candidates: the norm-fed sites (`attn`, `mlp`, `head`)
  on `staticch` at 8 or 10 bits, or on `p2row` at 10; `out` on `p2row` at 8 or 10, or
  `static` at 12; `down` on `p2row` at 9, 10 or 12, or `dyng128` at 8; weights `w8p2`,
  `w9p2`, `w10p2`, `w8m2`, `w8m3` and `w8`; two candidates with room on the norm-fed
  sites. The list is in `stage_configs('C2')`.

Decision rule: the limit of stage C stands (the simulated baseline plus 0.25%). A static
format is admissible on a site only if stage B2 counts no saturated element for it on
the scored windows, or with the room that removes them. Among the passing admissible
candidates the recommendation is the cheapest by the cost table above, with a code above
the single-matmul width of its weight format counted as one more lookup position per
input element. If none passes, the recommendation of stage C stands: a power-of-two row
scale at 10 bits on every site.

Budget: one more GPU-hour.

## Results of the addendum

Not run when this addendum was committed.
