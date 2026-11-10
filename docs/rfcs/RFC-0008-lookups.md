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

Status: Accepted. Question Q31. Companion RFC-0012 A8. ADR-065.
Review: [Workflow 02 passes](../../agents/reviews/logup-a2-acceptance.md).
Evidence: [algebra and counterexamples](../../formal/logup-characteristic.md),
[grouped units](../../formal/weighted-logup.md), [fraction reduction](../../formal/fraction-reduction.md),
[whole schedule](../../formal/lookup-consumers.md), [native contract](../../formal/native-lookup.md)
and the [exact finite study](../../research/logup-characteristic/REPORT.md).
Earlier research passes: [characteristic](../../agents/reviews/logup-characteristic-study.md),
[grouped units](../../agents/reviews/weighted-logup-study.md).
Motivation: p repetitions of an invalid tuple vanish from the ordinary LogUp
identity in characteristic p; extension fields and repeated challenges do not
repair it. The cited LogUp-GKR theorem has a characteristic hypothesis absent
from §§1–2. Cross multiplication also needs nonzero bound denominators.

Exact replacement for the multiset-inclusion claim of §1, the acceptance
semantics of §2 and the error statement of §6. §§2–3's tree shape and cost
terms are realised by A3/A5 as below; §§4–5 are unchanged.

1. **One mode.** Every lookup runs the grouped-equality-unit protocol of A5,
   exactly as [formal/native-lookup.md](../../formal/native-lookup.md) fixes it:
   statement and proof bytes, the eight stele/v0.1/lookup/ labels and their
   order, A3 trees and SelectedProduct, A9 consumers, errors, resources and
   abort rules. The unit-multiplicity equation of §1 with error (N+|T|)/|K|
   is withdrawn: p copies of an invalid tuple cancel in it. Also withdrawn:
   §1's "virtual or committed" tuples and F-valued multiplicities m in
   F^{|T|} (A5's are K-valued, item 4), and §2's stacking of all instances
   that use one table into one sumcheck (each A5 instance has its own trees).
   No partitioned, other weighted, field-switched or truncated variant is
   admitted.
2. **Static count bound (bound certificate).** The verifier derives the A5
   Statement from the public plan and profile, never from the proof:
   - N=2^m with 2^m the least power of two at least the plan's lookup
     positions for this instance, counted over every stacked layer, head and
     repeated value; a c-column tuple is one position; m<=59;
   - b=min(m,30), so each group holds at most 2^b<=2^30<p positions;
   - r=1 and d=4 (QM31) for standard; r=2 and d=8 (OM31) for treaty
     (RFC-0002 §8 with item 8: treaty needs both under Fiat–Shamir);
   - sigma as in item 3, from the plan's real positions, never supplied.
   Every other Statement field (lookup id, multiplicity ids and layouts
   (ell, blowup), source order and certificates, Table) comes from the
   consuming operation's Accepted RFC, today RFC-0023 §2.3 and RFC-0024
   §§1.1, 2.3. A consumer without such an RFC is not admitted.
   For m<=30 this is the ordinary unit-weight lookup over N<p positions (h=0,
   no Unit draw). For m>30 every group still has fewer than p positions and
   h=m-30 Unit draws weight the groups. Observed honest multiplicities never
   enter the bound. Plan admission rejects any other b with GroupBound, and
   any other r, d, N or sigma with Statement, before the first transcript
   absorb. A5's wider
   conditional range b<=min(m,30) stays available to its own primitive tests;
   no plan lookup may use it.
3. **Selectors and padding.** sigma is the verifier's Boolean indicator of
   the plan's real lookup positions; positions padded up to 2^m and masked
   entries are 0. Inactive leaves are the neutral (0,1) through
   1-sigma+sigma*(alpha-z_beta(x)), proven against that same sigma by A3
   SelectedProduct. Table rows beyond t are (0,1) leaves with logical-prefix
   multiplicities (A5 §2). Which positions are real is plan semantics
   (RFC-0005); this amendment binds the proof to the verifier's sigma.
4. **Sources.** Each tuple column is an original source with a verified A9
   certificate whose context is in Statement, bound before every Unit, Beta
   and Alpha draw. Every SelectedProduct column claim is consumed by an actual
   A9 point opening. Virtual (uncommitted) tuple columns are not admitted:
   the grouped theorem needs each column fixed before the Unit draws, and no
   Accepted claim-graph producer establishes that. Admitting one needs its own
   amendment; this replaces §2's "virtual → further reductions". A2 adds no
   cut and no committed tensor: multiplicities are A5's registered table-side
   sources, one per lookup instance and repetition (not once per table).
5. **Compression and order.** z_beta(x)=sum_a beta^a*x_a with c in {1,2}
   and t<=65536 real table rows. Order: Statement (sources, Table, sigma),
   then all r Unit vectors, all r multiplicity contexts, all r (Beta, Alpha)
   pairs, then trees and consumers, per A5 §4.
6. **Poles and retries.** Both root denominators must be nonzero (A3
   check_roots) before cross multiplication; any pole, sampler exhaustion or
   other failure aborts the whole attempt. The honest prover is deterministic
   (INV-8) and no protocol path resamples: no retry with fresh challenges,
   salt, fallback or partial acceptance. An honest attempt meets a
   pole only when some alpha_j equals a compressed table row, with probability
   at most r*t/|K| (inactive and padding leaves have Q=1; products of nonzero
   children are nonzero). This is a completeness failure, not a soundness term.
7. **Degrees and rounds.** Per repetition: lookup tree depth m, table tree
   depth k=log2(n), SelectedProduct m rounds; every A1 round has degree 3.
   Rounds r*[m(m-1)/2+k(k-1)/2+m]; draws r*h Unit, r Beta, r Alpha, r*(m+k)
   Gamma and r*(m+k) Fold (A5 §5).
8. **§6 errors.** The interactive identity term is e_LU^r with
   e_LU=min(1,(h+N+c*t-1)/|K|), under A5's schedule only. Tree, leaf, PCS,
   binding and Fiat–Shamir terms are charged as A5 §5 lists, never squared.
   e_LU^r is not a Fiat–Shamir bound. Hand derivation, for Q12 to
   formalise: all r Unit vectors come from one transcript state and all r
   (Beta, Alpha) pairs from another. Grinding the Statement re-rolls the
   unit round, whose error is about r*h/|K|; grinding free multiplicity
   bytes (e.g. physical tails) re-rolls the pair round, whose error is about
   e_LU^r, because one state cannot be split across repetitions. Under
   RFC-0012 §4's charge Q times the largest round error, with treaty Q=2^100
   and target 2^-128: r=1 on OM31 gives about 2^-108 at m=40 and 2^-114 at
   m=34, and fails; r=2 on OM31 gives about 2^-144 (unit round) and passes;
   d=4 gives a unit round near 2^-20 and fails. So treaty requires both
   r=2 and OM31. No standard-profile Fiat–Shamir bound is claimed: under
   the same charge with Q=2^80, QM31 at r=1 fails at real shapes (pair round
   near 2^-10); E12-02 and Q12 own that. Each repetition opens its own multiplicity source (A5); §6's
   single batched opening is withdrawn. OM31 changes |K|, not the
   characteristic, so it never replaces the count bound. Profile admission
   (totals, Q12) stays with RFC-0012.

Interfaces consumed, not provided here:

- **PCS.** A9 is binding but reveals row combinations. A private PCS (RFC-0010
  A3/A6) may replace it only through an amendment that keeps: a unique fixed
  near message bound before the Unit draws; point openings for every source
  column and the one or two prefix-mask functionals for each multiplicity
  vector; each with its own accounted loss, at the same transcript positions.
  The identity argument above uses only these properties.
- **Zero knowledge.** None is claimed. RFC-0013 A1 owns masking of sources,
  multiplicities and sumchecks; A2's soundness does not depend on hiding.
- **Ownership.** The proof is bound to the A9 certificates in its Statement.
  That those are the same handles the tensor's producer and consumers use is
  plan/claim-graph work (RFC-0005, E5), not discharged here. Values at
  positions with sigma=0 are unconstrained; no consumer may rely on them.
- **Fiat–Shamir.** Q12. **Integer ranges.** Membership is of field tuples;
  integer range discipline stays with §5, A1 and RFC-0021's canonical lift.

Real shapes (planning projections of docs/cost-model.md §3, 1.5–3 lookups per
activation element, one per attention score): stacked Llama-3.1-8B activation and exp lookups are
1.1–3.9·10^10 positions (N/p about 5–18, m=34..36); 405B reaches 5.7·10^11
(m=40). Ordinary unit weight cannot take one such instance. With b=30 they
need h=4..10 Unit draws; at c=2, t=2^16, the interactive log2 e_LU is
-84..-90 for QM31 and -208..-214 for OM31 at r=1. These shapes are not yet
runnable: tuple columns must be committed A9 sources of N entries (2N
committed elements for c=2), the Statement carries N selector bytes and the
verifier builds O(N) scratch. They need either a committed-source producer
or a virtual-column amendment, plus a succinct structured selector. Under
b=min(m,30) the weighted path (h>0) starts at m=31; practical positive tests
of it stay A5 primitive tests with b<m, which plans may not use.

Controls: NC-0400..0403 and NC-0415..0419 keep their A5 consumers (NC-0415 is
the count-bound control, NC-0416 the zero-root control, NC-0402 the padding
selector). Reserve as todo, without coverage credit: NC-0420, plan admission
with m=3 and b=2 instead of 3 rejects GroupBound; NC-0421, a treaty admission
with r=1 rejects Statement; NC-0422, a treaty admission with d=4 rejects
Statement; NC-0423, m one above the plan's least power of two rejects
Statement; NC-0424, one padded position marked selected rejects Statement.
All reject before the transcript; E3-07 implements them.

Soundness: no new challenge, label or loss; the LU record is RFC-0012 A11's
joint record, now required by RFC-0012 A8. The capped/wide/limb A2 evidence
continuations below remain Draft research evidence. Cost: A5's terms, which
include committing every tuple column and the O(N) selector; for m<=30 no
Unit draw or weighting occurs. c_lu, measured by E3-07, includes the A9
source openings. No constant or weight pass changes. Affected tasks: E3-07
becomes ready with all original criteria; E3-08, E8-05, E12-02/E12-03 and
lookup consumers must use this mode within the limits above. E7-05 (silu_q),
E7-06 and E7-07 (attention exp lookups) look up virtual tensors (RFC-0001
§3, RFC-0009 §1 step 4 and A4, RFC-0007 silu_q), so they are also blocked
on the Q31 virtual-column amendment.

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

### A5 — Conditional grouped lookup with actual certified consumers

Status: Accepted. Question Q31. Companions RFC-0012 A11 and RFC-0020 A6.
Review: [coordinated skill sign-off](../../agents/reviews/lookup-contract-accepted.md).
Exact contract: [native lookup](../../formal/native-lookup.md).
Motivation: A3 supplies the arithmetic but leaves full source/multiplicity
consumption unspecified. A9 supplies M31 sources; weighted multiplicities are
K-valued and need an explicit authenticated interpretation, not a type cast.

Addition to §2, as a separate conditional field protocol:

> Implement only the exact grouped-unit, wire, transcript, error and resource
> contract in formal/native-lookup.md. Use actual A3 trees/selected products,
> complete canonical RFC-0021 tables and actual A9 original point openings.
> Represent each repetition's multiplicities by canonical M31 limbs under an
> expected A9 context, reconstructing K values in the RFC-0003 A1 basis.
> Define logical table tails by prefix projection; consume their actual MLE
> through the contract's one or two separate rank-one functional openings.
> Physical tail zeros are not inferred from a certificate. Every original
> and every structurally present piece remains mandatory, even at zero weights.
>
> Bind all original contexts/table/selectors before independent unit vectors;
> bind all multiplicity contexts/certificate identities before every beta/alpha.
> Use the specified nonzero-root and public table-denominator consumers.
> Borrow actual caller-owned verified certificates and return only actual
> conditional records after complete consumption. Imported certificate bytes
> match opaque handles through A9's charged digest identity, never a trusted
> metadata receipt. Preserve failure usage, checked limits and abort semantics.

The mathematical scope adopts weighted-logup.md §§1-3 for the stated fixed-data
interactive identity and the exact deterministic limb/prefix lemma in the new
contract. A3/A9 retain their existing conditional hypotheses and individual
losses. Repetitions square only the joint identity event. Q12, external source
ownership, range discipline and joint privacy remain unresolved; neither profile
is admitted. This is not acceptance of Draft A2/A8 or of the revealing study
as a production PCS. No lookup value or tree intermediate becomes a cut.

A conditional prerequisite E3-07b must deliver complete native bytes/consumers,
real controls, independent parity and complete resource ledgers before done.
E3-07 retains every original NC-0400..0403, c_lu, committed-multiplicity and
private/full-lookup obligation. Reserve NC-0415..0419 as todo; no specification
or research check earns execution coverage. Cost terms are c_lu/c_sc/c_c and
T_misc, including actual registration, both trees, all openings and retained
state. No measured constant, performance result or weight-pass change.

### A6 — Development-profile tuple originals (companion of RFC-0026)

Status: Accepted. Review: [RFC-0026 acceptance](../../agents/reviews/rfc0026-acceptance.md).
Motivation: A2 item 4 requires each tuple column to be a whole original source
with a verified A9 certificate. RFC-0026 commits columns inside commitment
groups, offsets ranges and reads columns through variable maps.

Addition to A2 item 4, under the RFC-0026 development profile only. A tuple
column may be any of the following:

1. a column of a commitment-group source. Its claim is the source claim at the
   column's Boolean index coordinates (RFC-0026 §2.3);
2. an affine shift `v − w` of such a column, with a public constant `w`. A range
   check uses `w = width.min()`, and the verifier adds `w` back to the claimed
   value;
3. a `Ref`-mapped read over a domain of `2^m` positions. The column is evaluated
   at the lookup point restricted to the `Ref`'s variables, and may broadcast
   over a larger domain.

Reduction: the A5 argument needs one thing from each original: a function on
`{0,1}^m` whose multilinear extension the verifier can query through a sound
claim, fixed before the Unit, Beta and Alpha draws. All three forms are
multilinear in the lookup point, because a variable map is a restriction or
permutation and a shift is affine. Each claim reduces exactly to a claim on a
committed source whose root is absorbed before every lookup challenge (RFC-0026
§4 steps 2 and 5). The A5 identity, the tree and leaf terms, and the LU line
(item 8) are therefore unchanged, and no new loss arises.

- Item 5 still applies: `c ∈ {1, 2}` and at most `2^16` real table rows.
- Item 2's Statement is derived as RFC-0026 §4 step 5 states.
- Multiplicity sources are opened exactly as A5 specifies.
- Virtual (uncommitted) tuple columns remain not admitted.
- Cost-model terms: none. Affected tasks: E16-02.

### A7 — Committed-fraction proof of the A5 identity, for the zero-knowledge development path

Status: Accepted, conditional scope only: the dev-zk profile of RFC-0013 A4.
Question Q29. Task E12-17. Evidence:
[masked claims note](../../formal/zk-claims.md) §2.2. Companion of RFC-0013 A4.
Review: [RFC-0013 A4 acceptance](../../agents/reviews/rfc0013-a4-acceptance.md).

Motivation: A3/A5 prove the two fraction sums of the A5 identity with GKR
fraction trees. The tree layers are not committed, so each layer claim is a
revealed value that zero-knowledge would have to randomize separately. Under
RFC-0013's masked-claim construction every revealed claim must be on a
committed column, through a cube-sum relation. A7 keeps A5's statement and
replaces only how the fraction sums are proven.

Proposed text (for the RFC-0013 dev-zk composition only; A5 is unchanged for
every other use):

1. **Statement.** A5's grouped-unit identity exactly: the same tuple
   compression by `β`, the same unit vectors and repetitions, the same K-valued
   multiplicities by M31 limbs, and the same nonzero-root and table-denominator
   rules (formal/native-lookup.md). The domain is padded to at least `c_D + 1`
   variables (formal/zk-claims.md §2.1a), and the multiplicities scale with the
   padding.
2. **Fraction columns.** After `α`, the prover commits, as hiding sources, the
   K-valued columns
   - `h_w(i) = u(i)/(α − ⟨x_i, β⟩)` over the lookup domain;
   - `h_T(t) = m(t)/(α − ⟨T_t, β⟩)` over the table.

   Each is stored as `D` M31 limb columns in the RFC-0003 A1 basis. `u` is A5's
   public unit weight, including the selector.
3. **Identities.** Two zerochecks in A1 form prove
   `h_w·(α − ⟨x, β⟩) − u = 0` and `h_T·(α − ⟨T, β⟩) − m = 0`. One cube-sum
   sumcheck proves `Σ_i h_w(i) − Σ_t h_T(t) = 0`. With every bound denominator
   nonzero (A5's rule), the first two force `h` to be the fractions, and the
   third is A5's identity.
4. **Losses.** A5's joint identity line is unchanged (`(N + |T|)/|K|` per
   repetition, squared over repetitions as A5 states). It adds the SC/RLC terms
   of the two zerochecks and the sum, and the PCS terms of the fraction
   sources. A3's tree terms are removed.
5. **Privacy.** Every claim is on a committed column (tuple columns,
   multiplicities, `h_w`, `h_T`) through a cube sum, so RFC-0013's masked
   claims apply. The table side is public, but `h_T` depends on the secret
   multiplicities, so it is masked like any witness column.

6. **Soundness, carried over from A5.** A5's argument (formal/weighted-logup.md
   §2) bounds the event that the rational identity
   `Σ_i σ_i U_i/(X − z_β(x_i)) = Σ_t μ_t/(X − z_β(T_t))` holds at a uniform `α`
   for false sources by `e = min(1, (h + N + c·|T| − 1)/|K|)` per repetition. It
   uses only that the sources, selectors and units are fixed before `β`, and that
   the multiplicities are fixed before `β` and `α`. A7 keeps that order. It
   commits `h_w, h_T` after `α` and proves three statements about them.

   If no bound denominator vanishes, the identities of item 3 hold on the cube
   exactly when `h_w(i) = u(i)/(α − ⟨x_i, β⟩)` and
   `h_T(t) = m(t)/(α − ⟨T_t, β⟩)` for every position. The cube sum is then the
   identity at `α`. A false sum therefore needs one of these events:
   - A5's event `e`;
   - a vanishing denominator, `α ∈ {z_β(x_i)} ∪ {z_β(T_t)}`, which has
     probability at most `(N + |T|)/|K|` because `α` is drawn after the `z` are
     fixed. A5's nonzero-root consumers already reject this case. Under A7 the
     prover aborts (`DenominatorZero`), and the verifier also rejects a zero
     table denominator (`T̃` is public);
   - the SC/RLC failures of the two zerochecks and the sum;
   - the PCS terms of the fraction sources.

   The characteristic argument is unchanged. Group counts `n_{S,g} ≤ B < p`
   enter only through `e`. Padding multiplies counts by `2^pad`, and the plan
   keeps `B·2^pad < p`.
7. **Labels.** `θ`, `β`, `α`: A5's `lookup/unit`, `lookup/beta` and
   `lookup/alpha`, in A5's order. Each fraction source's root is absorbed with
   RFC-0012 A16's `relation/roots` after `α` and before the first zerocheck
   draw. The zerochecks and the sum are RFC-0013 A3 bound masked A1 instances,
   with A1's labels. No new label.
8. **Ledger.** Per check:
   - A5's LU line `e`;
   - the new line `(N + |T|)/|K|` (zero denominator, RLC family);
   - two zerochecks (SC `m·4/|K|` each, plus their `τ` lines);
   - one sum (SC `m·2/|K|`);
   - MASK and SC per masked instance (A3);
   - A9/A15 terms for the two fraction sources.

   A3's tree and leaf lines are removed for this profile.
9. **Costs (projection).** Per check, `D·N` M31 entries for `h_w` and `D·|T|`
   for `h_T`, each in a hiding source (A15: four times the message). On the
   eight-layer synthetic window (`T = 64`), the census counts 15 027 520
   looked-up entries. That projects to `≈ 6.0·10^7` M31 entries of `h_w`, or
   `≈ 2.4·10^8` with hiding, against `1.6·10^7` committed entries today. This
   term dominates dev-zk's commitment cost (RFC-0013 A4 item 9).
10. **Controls.** NC-0913 (one `h_w` entry changed, the source recommitted:
    `RoundSumMismatch` in its zerocheck) and NC-0914 (`h_T` shifted by a constant
    on two entries so the sum is unchanged: the `h_T` zerocheck rejects).
    Reserved `todo`.

Soundness impact: as item 8, for the dev-zk profile only. Affected tasks: E12-19
(implements A7) and E12-14.
