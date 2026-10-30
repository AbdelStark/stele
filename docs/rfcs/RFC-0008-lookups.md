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

A2 candidate continuation: [grouped equality units](../../formal/weighted-logup.md)
and [reproducible evidence](../../research/logup-characteristic/WEIGHTED.md),
reviewed in the [same-author record](../../agents/reviews/weighted-logup-study.md).
This proposes public groups of B=2^b<p positions, with canonical MSB-first group
ids and equality-basis units sampled after sources/selectors are fixed. One or
two K-valued multiplicity vectors are committed after the unit vectors and before
every alpha/beta. The lookup tree is ordinary within groups and weighted above
them; the table tree is ordinary. No correction divides by a unit. The derivation
accounts for compression and unit failures and distinguishes independent from
shared-unit repetitions. It also identifies the actual selector/source reduction
needed for neutral denominator leaves. These are candidate requirements, not
admitted bytes, challenge labels, K-valued commitment formats or implementations.
The original actual consumer, privacy, native controls and complete c_lu gates
remain required; E3-07 stays blocked on A2.

A2 fraction continuation: [conditional reduction](../../formal/fraction-reduction.md)
and [executable evidence](../../research/logup-characteristic/FRACTION.md) fix a
candidate descriptor, per-layer P/Q combination, all-child Final absorption and
canonical child-coordinate fold. A separate selected-product sumcheck consumes
the lookup denominator and exports every original tuple column. Exact public
consumers close the research computations; committed K-valued multiplicities,
private source consumers, full plan/bytes, native controls and costs remain
required. No new intermediate commitment or Accepted protocol is introduced.

A2 consumer continuation: [whole schedule](../../formal/lookup-consumers.md) and
[exact study](../../research/logup-characteristic/LOOKUP.md) connect the two trees
to source roots, pre-challenge K-valued mu roots and exact table padding. A
revealing Merkle adapter authenticates full original vectors and consumes every
derived claim. It is research evidence for binding/composition, not the required
private PCS, ZK, native control or c_lu implementation. The full private consumers,
plan/wire admission and all original E3-07 criteria remain prerequisites.

### A3 — Conditional fraction-tree and selected-product reductions

Status: Accepted. Question Q31. Review: [skill passes](../../agents/reviews/fraction-a3.md).
Evidence: [tree argument](../../formal/fraction-reduction.md) and
[closed computation](../../formal/lookup-consumers.md). Companions: RFC-0012 A9,
RFC-0020 A4. This implements the common arithmetic prerequisite without admitting
a lookup mode, private consumer, revealing production PCS, profile or inference
statement. A2 remains Draft; E3-07 retains every original requirement. E3-07a
delivers the conditional native primitives, controls, parity and primitive ledgers.

Addition to §2, as a standalone conditional reduction:

1. Only canonical QM31/OM31 are supported. The immutable verifier-owned descriptor
   has u64 tree id, u32 m,b with 0<=b<=m<=63, two distinct u64 leaf ids and m-b
   K elements theta in MSB-first order. It is supplied by the consumer, never
   adopted from proof metadata. Generic arithmetic does not admit a weighted
   lookup: the complete protocol must separately enforce A2's static count bounds.
   Original arrays are fixed before relevant challenges and have 2^m pairs (P,Q).
2. At parent layer k from the root, a=1-theta[k],z=theta[k] when k<m-b, otherwise
   a=z=1. Children are adjacent: P=a*P0*Q1+z*P1*Q0, Q=Q0*Q1. Bind descriptor and
   both roots. For each k<m bind tree id,k,r,p,q before Gamma. A1 proves sum
   p+gamma*q on k variables with ordered inputs P0,Q0,P1,Q1,Eq(r,.) and terms
   a*P0*Q1*Eq + z*P1*Q0*Eq + gamma*Q0*Q1*Eq. Zero coefficients retain degree 3.
3. A1 absorbs all five finals. Check Eq(r,u) exactly, then draw Fold tau and
   propagate p'=(1-tau)*p0+tau*p1, q'=(1-tau)*q0+tau*q1 at (u,tau). The appended
   coordinate is the canonical child bit. Local child ids 0..4 never escape.
   k=0 still draws Gamma/Fold around a scalar A1 final; m=0 has no layer or draw.
   Export exactly the two original leaf claims. Every final, including unused
   values, needs an actual original reduction/opening consumer. A public adapter
   checks original arrays. No receipt alone accepts lookup membership.
4. Q=0 is allowed for generic pair arithmetic. The separate root consumer requires
   both denominators nonzero, then checks cross multiplication. This check alone
   is not lookup acceptance. Any failure or sampling exhaustion aborts the attempt;
   no resampling, fallback, new intermediate commitment or partial acceptance.
5. The selected-product leaf consumes p,q at r, fixed alpha,beta, fixed public
   Boolean sigma and c>0 distinct ordered original ids >=2. Check p=sigma_tilde(r).
   Prove H=1+(alpha-1)*p-q with degree-three A1 terms beta^j*Eq(r,.)*sigma*x_j,
   j=0..c-1, input ids [0,1,original ids]. Bind descriptor,c,original ids,
   alpha,beta,r,p,q first. Check final Eq and sigma independently, then emit every
   original column at the same point, including zero-coefficient columns. A public
   adapter consumes all actual columns. This is the MLE of a Boolean selected
   product, not a product of separately evaluated MLEs.

Canonical encoding and resource contract:

- All integers are little endian; K values use canonical RFC-0003 limbs. Reject
  noncanonical limbs rather than reduce them. Descriptor: u8 version=1, u8 field
  degree, u64 id, u32 m, u32 b, two u64 leaf ids, then theta. Proof: two K roots,
  then for k=0..m-1, k A1 rows of four K values and five finals. Exact length is
  4d*(2+2m^2+3m). No points, counts, ids or extra bytes are adopted from the proof.
  Decode against a validated descriptor; reject short/trailing bytes before
  allocation or absorption. Decoding produces an unverified proof object only.
- The leaf A1 payload has m rows of four values and c+2 finals, exact length
  4d*(4m+c+2). Scalar boundaries retain their prescribed finals. All sizes,
  shifts and allocations are checked. The verifier never allocates 2^m from a
  proof. Dense prover/public-consumer materialization rejects Capacity when its
  actual buffers cannot fit; complete protocol/profile resource admission remains
  mandatory. Both-field codec tests compare decoded fields, not just round trips.
- Fraction absorbs descriptor+roots; Layer absorbs u64 id,u32 k,r,p,q; Leaf absorbs
  descriptor,u32 c,c u64 original ids,alpha,beta,r,p,q. A1 framing is unchanged.
  Tree SC id=k is local to its preceding frame; leaf SC id=tree id is scoped by
  Leaf. Tag accounting records by tree and phase/level; equal local ids from
  different invocations must not overwrite one another.
- Invalid descriptors, proof shapes/lengths and field encodings have distinct
  typed errors. A parser supplies no transcript/consumer check. Native engine
  parity must cover proofs, decisions, original claims, records and continuation.

Soundness: F(m)/|K| for the tree, F(m)=3m(m-1)/2+2m, conditional on true original
leaf evaluations. Gamma and Fold each contribute m/|K|; scoped A1 records sum to
3m(m-1)/2 over |K|. The selected-product leaf adds 3m/|K|. Exact root/Eq/public
selector checks add no random loss. The explicit argument is in the linked
fraction note. PCS/binding, source authentication, full lookup identity, ZK and
FS/H remain separate; Q12 is unresolved and GKR losses are not automatically squared.

Implementation order: canonical types/bytes, native engines and actual public
consumers, real controls, shared parity corpus, then complete primitive ledgers.
None alone completes E3-07a. NC-0406..0410 are reserved; research/codec checks
earn no coverage. E3-07 retains NC-0400..0403, committed multiplicities, private
integration and measured c_lu. Cost terms: c_lu/c_sc, T_misc and owned source,
tree, proof and coefficient storage. Use linear-size equality construction and
charge all retained levels/copies. No fitted constant or weight-pass count changes.

### A4 — Canonical public table registry and function closure

Status: Accepted. Companion RFC-0021/RFC-0004 A4. Review: [coordinated skill sign-off](../../agents/reviews/cqis-functions-contract-accepted.md).
Motivation: §4's concatenation lacks field boundaries and conflates complete
functions with small lookup components. A table name/id alone also cannot
authenticate arbitrary supplied rows or a changed decomposition.

Exact replacement for §4: RFC-0021 defines the closed component TableId schemas,
canonical integer data, FunctionId, RepresentationId and exact function manifest.
Each registered lookup component has at most 2^16 padded rows. Large exponential
functions use the selected explicit composition; the verifier derives its complete
integer relations, input domains and component identities from authenticated
configuration. Unknown roles, swapped components, parameter aliases, missing/
additional components and a representation different from the plan reject.
RoPE is a public tensor under RFC-0017, not an entry in this closed lookup registry.

Before direct MLE use, validate the complete component definition/data and lift
integers canonically as RFC-0021 §4 specifies. Wrapper openings instead reference
the exact RFC-0011 A2 table matrix/root, plus the complete Accepted opening
protocol; mere inclusion under a supplied root is insufficient. The same padded
row order and valid-row selector apply in both paths. Range discipline and all
original-source/multiplicity consumers remain mandatory; a generated table is
not an authenticated source or a verified lookup.

No A2 lookup mode, private consumer, transcript label or profile is admitted.
E3-07's existing block and all original E3-08 controls remain. NC-0412/0413/0414
are reserved for actual function/representation/data binding consumers; no research
credit. Costs are O(Lc) public evaluation plus the actual per-component c_lu and
recombination/range c_a; table generation is T_misc. No measured constant, new
commitment category or weight-pass change. All actual losses retain ledger lines.

### A2 evidence continuation — Byte membership in capped scalar relations

Status: Draft. Q26/Q31 [range consumer evidence](../../research/cqis-bounds/CAPPED-RANGE.md)
uses the exact range_8 table and all-one selectors over eight byte planes per
padded scalar row. Its complete Q31 lookup terminates at actual revealing source
and multiplicity consumers. Four subsequent A3 relations consume the same bound
bytes, a canonical scalar source and a carry vector. Invalid selected byte values
fail the lookup equation even when their field-valued column arithmetic is valid.
This accepts no private auxiliary commitment, native plan, source/PCS interface,
profile or new label. Full original A2/E3-07 and model range-discipline obligations
remain; conditional composition is recorded in the soundness-accounting document.

### A2 evidence continuation — Exact wide-word byte membership

Status: Draft. The [wide range study](../../research/cqis-bounds/WIDE-RANGE.md)
uses one ordinary Q31 unit over 2BN source/complement bytes, with N<=4096
and B<=32 derived from expected unsigned caps. Its static selected count is
below p; every byte, including padding and high planes, remains selected.
The original byte-word source is independently root-bound and connected to
the lookup's first half by consumed A3 claims. Complement/carry relations then
enforce the exact cap. Conditional identity and reduction errors stay separate.
This admits no private auxiliary root, production plan, range dominance rule,
profile or label; full A2 and E3-07 obligations remain.

### A2 evidence continuation — Limb digit and whole-word consumers

Status: Draft. The [limb source study](../../research/cqis-bounds/LIMB-SOURCE.md)
retains the complete range_8 lookup schedule and actual original consumers in
each nested wide-word proof. A one-byte cap15 consumer proves canonical nibble
digits without inventing a new range table. Original digit views and the bound
whole-word bytes meet at an additional consumed A3 packing relation. Separate
lookup identities/reductions and A3 errors are added under their existing
conditional hypotheses. Native range dominance, complete source/plan consumers,
private PCS/ZK and all E3-07 criteria remain required; no profile or label changes.
