# RFC-0008 — Lookups: LogUp-GKR, table registry, range discipline

Status: Accepted · Version: 0.1.0 · Depends: RFC-0006

## 1. Statement
For a table `T ⊂ F^c` (tuples of `c` columns, `c ∈ {1,2}` typically `(in, out)`), lookup tuples `x_1..x_N` (virtual or
committed), selector `σ_i ∈ {0,1}` (public MLE, excludes padding/masked entries), multiplicities `m ∈ F^{|T|}` (committed):
`Σ_i σ_i / (α − ⟨x_i, β⟩) = Σ_t m_t / (α − ⟨T_t, β⟩)` with `⟨·,β⟩` the column compression by `β`.
`α, β ∈ K` from the transcript. Implies multiset inclusion with error `(N + |T|)/|K|` (Haböck 2022).

## 2. LogUp-GKR (Papini–Haböck 2023)
Both sides are fraction sums evaluated by a binary tree of `(p, q)` pairs:
leaf `(σ_i, α − ⟨x_i,β⟩)`; node `(p_0 q_1 + p_1 q_0, q_0 q_1)`; root `(P, Q)`, check `P_lookup·Q_table = P_table·Q_lookup`.
Each tree level is one degree-3 sumcheck (stacked over all instances using the same table). The leaf-level sumcheck's
final claim is `σ̃(r)` (public) and `⟨x̃(r), β⟩` — the prover sends `x̃_col(r)` per column, which become claims on the
input tensors (virtual → further reductions). **No lookup value is ever committed.** Multiplicities are committed once per table.

## 3. Cost
Leaves: 1 K-sub + 3 K-mults per pair ≈ 3 K-mults/leaf; GKR sumchecks ≈ 6 K-mults/leaf amortised; total `c_lu ≈ 60–150`
M31-mults (bench constant). Memory: the tree is built level by level and discarded (streaming, RFC-0014).

## 4. Table registry
`TableId = H(name ∥ definition_version ∥ params)`. Registered tables: `exp_q`, `silu_q`, `rsqrt_q`, `range_8/12/16`,
`gelu_q`, `softcap_q`, `sigmoid_q`, `rope_cos/sin` (public tensor, not a lookup). Large tables are **defined** as
compositions of small ones (RFC-0004 §4) so every registered table is ≤ 2¹⁶ entries. The verifier evaluates `T̃(r)`
directly (2¹⁶ K-ops) or, in the wrapper, via a passport-committed table MLE opening (RFC-0016 §4).

## 5. Range discipline (every committed/cut element's range is enforced exactly once)
- A lookup `(in, out)` into a registered table enforces `in ∈ domain(T)`; this *is* the range check of `in`.
- Requant remainders use `range_e` decomposed into `range_12`/`range_8` chunks.
- Cut tensors (int16) are range-checked by the first table that consumes them (RMSNorm's limb split enforces int16) — the
  plan verifier (`stele-ir::check_ranges`) refuses a plan where any committed element lacks a dominating check.

## 6. Treaty profile: double challenge (ST-6)
Two independent `(α, β)` pairs are drawn after the multiplicities are committed; the full fraction-sum protocol runs for
each; the multiplicity commitment is opened once with both batched functionals. Error `((N+|T|)/|K|)²`. Alternative:
octic challenge field (RFC-0019 R-OCTIC). Standard profile: one pair.

## 7. Negative controls
NC-0400 multiplicity inflated by one; NC-0401 lookup value outside table; NC-0402 selector flipped to include a padding
row; NC-0403 second challenge pair reusing the first; NC-0404 table id mismatch with passport; NC-0405 decomposed
table recombination wrong by one.
