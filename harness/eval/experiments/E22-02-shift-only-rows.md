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

## Results

Not run when this file was committed.
