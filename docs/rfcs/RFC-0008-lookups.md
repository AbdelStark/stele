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

## 8. Amendment log

### A1 — Range discipline for packed source decompositions

Status: Draft. Question Q28. Companion RFC-0010 A6 and RFC-0007 A1; evidence:
[packing obligations](../../formal/packed-commitments.md).
Motivation: an integer packing equality permits noncanonical alternative digits
unless their ranges and relationship to the same source are actually enforced.

Proposed addition to §5:

> For a packed committed source, the dominating-check analysis must include the
> canonical word range, every digit/fragment range, signed reconstruction,
> position mapping and all tail/message padding. Each check must refer to the
> same source and use the plan's registered decomposition. Checking the original
> format label, a revealed honest source, or only a field recombination is not
> a private decomposition proof. Every original claim must reach its actual
> reduction/PCS consumer. Bound certificates are static and verifier-recomputed.

The exact reduction, table identities, claim schedule, privacy and controls are
required before acceptance. Candidate range-15 parts in packed30 are not newly
registered tables. NC-0603/0405 need their real consumer; research checks do not
earn credit. No production challenge or loss changes; future terms need ledger
lines. Decomposition moves c_lu/c_a/T_misc and memory, with no measured constant
or benchmark supplied here. Affected tasks: E3-08, E4-03, E5/E6 range lowering and
E7/E10 packed consumers; all original acceptance criteria remain.

### A2 — Characteristic-safe multiplicities and nonzero denominators

Status: Draft. Question Q31. Companion RFC-0012 A8.
Evidence: [algebra and sources](../../formal/logup-characteristic.md),
[exact finite study](../../research/logup-characteristic/REPORT.md).
Review: [same-author skill passes](../../agents/reviews/logup-characteristic-study.md).
Motivation: p repetitions of an invalid tuple vanish from the ordinary LogUp
identity in characteristic p; extension fields and repeated challenges do not
repair it. The cited LogUp-GKR theorem has a characteristic hypothesis absent
from §§1–2. Cross multiplication also needs nonzero bound denominators.

Proposed replacement requirements for §§1–2 and clarification of §6, pending
the complete selected protocol and byte contract:

> Every ordinary unit-weight lookup instance has a verifier-derived static
> upper bound on its total selected positions strictly below char(K), not |K|.
> All batched columns/layers and every repeated selected value count toward
> that limit. Selectors are authenticated Boolean values with exact padding
> semantics. A bound based on observed honest multiplicities is insufficient.
> For larger instances, use a complete Accepted partitioned or weighted-unit
> construction with its own authenticated layouts, challenges and consumers;
> do not silently truncate, switch fields or reuse the ordinary formula.
>
> Fix exact tuple compression, coefficient powers and challenge order. Bind
> the original tuples/table before relevant challenges and multiplicities as
> required by the chosen theorem. Account explicitly for compression collisions
> and rational-identity error. Original source claims and table-side committed
> multiplicities must reach their actual consumers in every selected mode.
>
> An inactive/padded fraction leaf is the neutral (0,1), proven against the
> same selector used by the lookup. Active leaves follow the selected identity.
> Both root denominators must be nonzero, and all parent/leaf relations must
> be proven against the original sources. Cross multiplication or a nonzero
> supplied root alone is insufficient. Fix honest pole rejection and attempt/
> retry semantics in the transcript contract; no silent challenge resampling.
>
> If static partitions are selected, derive their exact source coverage and
> count bounds from the public plan; authenticate each partition's multiplicity
> table and equality independently, or use a fully accounted batching reduction.
> Merely adding the equalities can restore the characteristic cancellation.
> Weighted units are a distinct protocol with their own numerator/multiplicity
> representation and commitment order. No such mode is admitted by this Draft.
>
> Two repetitions square only an identity error under the applicable fixed-data
> and independent-challenge hypotheses. Shared preliminary failures, GKR checks,
> PCS, binding and Fiat-Shamir errors require their own composition. Neither
> repetitions nor OM31 cure the ordinary p-copy counterexample.

Before acceptance: select the full protocol, layouts/bytes/transcript labels,
static certificates, selectors/poles, tuple bound, exact GKR degrees/rounds,
source/table/committed consumers, privacy and all actual negative controls.
Preserve original NC-0400..0403 and c_lu gates; add real count-bound, zero-root,
padding/partition-coverage and mode-substitution controls with the implementation.

Soundness: no production record or challenge changes. The note proves conditional
bounded-count residue and power-compression bounds; it does not instantiate GKR,
PCS, ZK or Q12. Existing LU formulas must not admit an unsupported shape. Cost:
c_lu/T_misc, multiplicity/table work, commitments and peak state; no measured
constant or weight-pass change. E3-07 is blocked on A2; E12-02/E12-03 and lookup
consumers are affected. All original acceptance criteria remain.
