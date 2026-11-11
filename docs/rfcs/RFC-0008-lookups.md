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

### A7 — Zero-knowledge GKR over the A5 trees, for the dev-zk profile

Status: Accepted, conditional scope only: the dev-zk profile of RFC-0013 A5.
Question Q29. Task E12-17. Evidence:
[ZK-GKR note](../../formal/zk-gkr.md) (construction, soundness, privacy, and the
census cost comparison with committed fraction columns) and
`research/zk-claims/check_gkr.py`. Companion of RFC-0013 A5. Review:
[RFC-0013 A5 acceptance](../../agents/reviews/rfc0013-a5-acceptance.md).

Motivation: A3/A5 prove the A5 identity with GKR fraction trees whose layers
are not committed, so every layer claim and the roots are revealed values. A
first draft of A7 committed whole fraction columns instead, at about
`3.3·10^8` M31 entries on the eight-layer window. Masking the existing trees
costs about `4.2·10^5` (formal/zk-gkr.md §3). A7 keeps A5's statement and trees
and masks them.

Proposed text, for the dev-zk profile only; A5 is unchanged for every other use:

1. **Statement and order.** A5's grouped-unit identity, units, multiplicity
   limbs, `θ, β, α` and error `e`, in A5's order, one statement per check
   (RFC-0026 A3). Domains are padded per RFC-0026 A9. Multiplicities scale with
   the padding, and the plan checks `B·2^pad < p`.
2. **One fraction sum.** The lookup and table trees of a check are combined
   into one fraction tree, with the table numerators negated. Its sum must be
   zero. No root is revealed.
3. **Committed top.** Layer `k0 = c_D + 1` is committed after `α`, as hiding
   columns `p`, `q` and `h = p/q`. The root is absorbed with RFC-0012 A16's
   `relation/roots`. RFC-0013 A5 relations prove `h·q − p = 0` and `Σ h = 0`. A
   zero `q` entry at the top aborts the producer (`DenominatorZero`). Below the
   top, a zero denominator is A5's existing nonzero-root rule.
4. **Masked layers.** For every layer below `k0` and each of `p, q`:
   - a `4D`-entry mask block on coordinates `(T, u)` in the proof's shared
     mask source (RFC-0013 A5 item 5a);
   - masked values `V̇ = Ṽ + κ(X_v)·r̃(T, X_u)`;
   - one A1 sumcheck per step over a selector bit and the layer variables,
     whose `s = 1` half is `κ·eq(u, y)·r̃(t*, y)`, masked by the shared source.

   Its finals are four masked layer values and one block claim. The existing
   A3 fold challenge `λ` and line challenge combine them (`FractionGamma`,
   `FractionFold`). The producer aborts if a block's three revealed functionals
   have M31 rank `< 3D`.
5. **Leaves.** The last step's finals are RFC-0013 A5 masked claims on tuple
   columns and multiplicities. Selectors and tables are public.
6. **Losses.**
   - A5's `e` per check.
   - Per masked layer: SC `(k + 1)·3/|K|`, `λ` and line `2/|K|`, MASK `1/|K|`.
   - The top's A4 identity and sum terms.
   - The shared source's batch and opening terms (RFC-0013 A5).

   A3's tree terms are replaced by these. No new label.
7. **Cost (projection).** Eight-layer window, 21 checks, 570 layers: about
   `1.05·10^5` M31 mask entries, `4.2·10^5` with hiding. The trees are computed
   as today.
8. **Controls.** Reserved `todo`:
   - NC-0913: one masked layer value changed; the next step fails with
     `RoundSumMismatch`.
   - NC-0914: one mask-block entry changed after commitment; `RootMismatch`.

Soundness impact: as item 6, for the dev-zk profile only. Affected tasks: E12-19
(implements A7) and E12-14.

**Implementation notes (E12-19, ADR-100).** These make the items above exact.
Labels and the order of items 1–4 are unchanged.
- **Item 6's SC line.** A masked step's degree is RFC-0013 A5 item 3's declared
  degree, not 3. Each masked child raises its vanishing variable's degree, and both
  children `q(·, 0)` and `q(·, 1)` share `q`'s vanishing variable in `q0·q1`. The
  SC line is therefore `(k + 1)·δ_k`. This item replaces the `(k + 1)·3` of
  item 6. The degrees, all asserted by tests:

  | Step | `δ_k` | Why |
  |---|---|---|
  | first, `k = c_D + 1` | 7 | `u` is all of `x`, so `v ∈ u` |
  | `k = c_D + 2` | 7 | `q`'s vanishing variable lies in `y` |
  | middle, `k ≥ c_D + 3` | 5 | `v ∉ u` |
  | leaf | 4 | |
- **Zero-denominator line.** No root is checked under dev-zk. `h = p/q` at the top
  is sound only when no leaf denominator vanishes. For a committed tuple or table
  row, `α − Σ β^i x_i` is a degree-`c` polynomial in `(α, β)`, so by
  Schwartz–Zippel some leaf vanishes with probability at most
  `2^{n+1}·c/|K|` per lookup. This is LogUp's `(N + |T|)/|K|` pole event with the
  compression degree.
  - A5's `e` assumes nonzero root denominators, checked by `check_roots`. dev-zk
    replaces that check with the top identity, so the term is charged here, as a
    separate ZD line of `2^{n+1}·c/|K|` per lookup.
  - The honest producer's `DenominatorZero` abort is the completeness side of the
    same event.
- **Tree layout.** Leaf `(x, h)` has `h` last: `(1, α − Σ β^i x_i)` for the
  lookup and `(−mult, α − Σ β^i T_i)` for the table, padded rows `(0, 1)`. A
  parent combines `(·, 0)` with `(·, 1)`, so the line challenge `t*` is the last
  coordinate, as in A3.
- **First step.** The claim on the committed top is never sent. The first step is
  the zero-sum `Σ_x eq(r, x)·[F_λ(children) − V̇_p(x) − λ·V̇_q(x)] = 0`, on masked
  occurrences of `p` and `q`. `r` is drawn with `ZeroWeight`.
- **Later steps.** The `s = 1` half is `Σ_P λ^P·κ_P·eq(u_P, y)·[x̄ = 0]·r̃_P(t*, y)`.
  `y` is `x`'s last `c_D + 1` variables, and `x̄` is the rest.
- **Layer masks.** For a layer child, `v` is `x`'s first variable (for `p`) or
  second (for `q`), and `u = y`. Blocks lie in the shared mask source from data
  row `D` on, `4D` entries each, on `(T, y)`.
- **Aborts.** The producer aborts in three cases:
  - a layer child's `κ = 0` (`Vanishing`);
  - a block whose three functionals have rank `< 3D` (`ClaimRank`);
  - a zero top denominator (`DenominatorZero`).
- **Controls added.** All go through the composed verifier, and each fails when its
  check is removed:
  - NC-0917: a later step's head final changed;
  - NC-0918: a later step's selector final changed;
  - NC-0919: a false lookup whose top `h ≠ p/q` sums to zero, with the identity
    `h·q − p = 0` forged.

  NC-0917 and NC-0918 expect `ClaimMismatch`; NC-0919 expects `RoundSumMismatch`,
  at the shared batch.
- **Scope of E12-19.** One unselected member per lookup with `n ≥ c_D + 1`
  variables. Selectors (A5's selected product), several members, padding and A5's
  statement and unit messages are wired by E12-14, which composes the
  development proof.

**Implementation notes (E12-14a, ADR-101; development tier, pending independent
review).** These extend the E12-19 scope to every RFC-0026 A3 check. No label, loss
form or challenge changes.
- **Check tree.** The lookup half holds the check's members largest first, each
  padded to `m' = max(vars, c_D + 1)` variables (RFC-0026 A9) and aligned to
  `2^{m'}`. The tree has `n = max(c_D + 1, k, ⌈log₂ Σ 2^{m'}⌉)` variables, with
  the table of `2^k` rows padded to `2^n`. Lookup leaf: `(S, α − Σ β^i·S·X_i)`.
  `S` is the public concatenated selector, 0 off the members. `X_i` is the
  concatenated tuple plus its shift (a range's `−width.min()`). Table leaf:
  `(−Z·mult, T)` with `Z = [x_high = 0]` when `k < n`. An unselected position
  has `q = α`, so the ZD line `2^{n+1}·c/|K|` per check is unchanged.
- **Leaf instance.** With a selector, padding or several members, the leaf's
  inputs are `eq·Z`, `S`, a weight `W_m = B_m·S` per member and every member's
  masked occurrence. `B_m` is the public indicator of member `m`'s block. Every
  member claim is therefore a final, and every term has at most four factors.
  The verifier evaluates `eq·Z`, `S` and `W_m` itself (`ClaimMismatch`). The
  producer folds one combined factor per tuple entry. All member occurrences share
  one vanishing variable and `u` = the last `c_D` variables, which lie in every
  member's block. The declared degree is the larger of the two forms' degrees.
- **Statement and unit messages.** Before each check's `β`, `LookupStatement`
  absorbs the check index, `n`, `k`, `c`, the valid row count, the member count
  and each member's `(m', vars, offset)`. `LookupUnits` absorbs the index and an
  empty unit list (`b = m`, RFC-0026 A3).
- **Multiplicities.** Each selected entry of a member counts `2^{m' − vars}`
  times. They are committed in the witness source, before `β, α`.
- **Controls.** NC-0920..0923 cover members, selector, shift and padding. NC-0929
  covers the `S` final. NC-0930 (`W_m`) and NC-0931 (`eq·Z`) are `todo` (see the
  RFC-0013 A5 E12-14a notes).

### A8 — Standard-profile LU (β, α) nonce: bits, byte offset and multiplicity policy (companion of RFC-0012 A17)

Status: Accepted. Full path (Workflow 02 item 3). Task E12-24. Decision: ADR-108.
Review: the independent review of PR #347 (FIX-THEN-MERGE; its F1, Policy 2
originals, is fixed in item 3 and NC-0817). Companion of RFC-0012
A17 item 5, which says "An RFC-0008 amendment in E12-23 fixes the exact byte offset
before implementation"; ADR-106 moved that work to E12-24.

Motivation: A17 (C1) requires every reachable round to satisfy `ε_i·2^-k_i ≤ 2^-108`
under the standard profile. A QM31 (β, α) round can fail this without grinding; the
recorded stories42M range_8 round is `2^-97` (formal/fs-composition.md §6). A17 lets
LU rounds grind, but it leaves their wire position to this amendment. A standard
lookup also opens and certifies its own multiplicity sources. Under Policy 1 their
ungrinded QM31 tensor round `2·ℓ·(e+1)/|K|` can also fail (C1).

Exact addition, to A5 and formal/native-lookup.md §§3–4:

1. **Scope.** This amendment applies only to an A5 lookup admitted to the standard
   profile (`lookup::Descriptor::standard`). An A5 lookup with no profile
   (`Descriptor::new`), the RFC-0026 development checks (A6) and the dev-zk trees
   (A7) have k = 0, carry no nonce and keep Policy 1. Their bytes are unchanged.
2. **Bits.** Each repetition j has one (β_j, α_j) round (RFC-0012 A17 item 3,
   fs-composition.md Lemma 4), with error `a/|K|`, where
   `a = (c−1)(N+t) + N+t−1 = c(N+t) − 1`. Here N = 2^m positions, t = the Table's
   real rows and c its columns. k is the least integer k ≥ 0 with
   `a·2^108 ≤ p^d·2^k`, computed from the expected statement with exact integers.
   The same k serves every repetition. For d = 8, k = 0, because a < 2^62. If k > 32,
   the configuration is UnsupportedParameters (`Error::Statement`), and it is rejected
   before any transcript mutation. The unit round (θ, h ≤ 30 draws) is charged
   `h/|K| < 2^-108` and is never ground (A17 (C4)).
3. **Policy 2 sources.** Every source of a standard lookup uses Policy 2
   (RFC-0010 A14 item 1: standard means Policy 2).
   - Each multiplicity layout's A9 source is constructed with Policy 2. Its
     certificate and opening tensor and column rounds then grind as E12-23
     implements them. The policy byte is part of the 105-byte context that step 3
     already absorbs in Multiplicities.
   - Every caller-owned original certificate must carry Policy 2. Otherwise
     construction rejects with `CertificateContext`, before any transcript work. A
     Policy 1 original's certificate was verified with an ungrinded tensor round,
     which can fail (C1), so a standard lookup must not consume it.
4. **Transcript.** Exact replacement for native-lookup §4 step 4, under item 1's
   scope: "For j=0..r-1 absorb Repetition(u64 id,u8 j,u8 phase=0). If k ≥ 1, the
   prover sends nonce n_j and the verifier checks it, exactly as RFC-0012 A17 item 5
   specifies: one PoW query, then absorb on success. GrindMismatch aborts the attempt.
   Then draw Beta followed by Alpha. Finish all r pairs before any tree proof."
   This is the A17 placement: the nonce immediately follows the last absorb before
   `lookup/beta`.
5. **Wire.** If k ≥ 1, r u64le nonces n_0..n_{r−1} follow the r registration packets,
   in repetition order, and precede repetition packet 0. Nonce j starts at byte
   `2 + Σ_{i<r}(32 + C_i) + 8j`. The §3 total gains `8·r·[k ≥ 1]` bytes, and the
   absorb-payload bound gains `9·r·[k ≥ 1]`. Every u64 value is well formed. The
   predicate is checked at the transcript point in item 4, never during preflight.
6. **Prover.** It sends the least valid nonce (A17 item 5), so the proof stays
   deterministic (INV-8).

Soundness impact:
- Under item 1's scope, each (β, α) round's FS factor is `ε·2^-k ≤ 2^-108`, so (C1)
  holds, and k is the least such value, so (C4) holds.
- The interactive LU line (Lemma 4's numerator) is unchanged.
- The grinding registry line `stele/v0.1/grind` (A17 item 6) is already registered.
  No new label, challenge or loss line is added.
- The Policy 2 multiplicity rounds meet (C1) by RFC-0010 A14.
- Proven/conditional status is that of RFC-0012 A17 Theorem 1.
- Open: (C2) and (C3) over a whole standard proof, and the exact round enumeration,
  remain E8-05's.

Cost impact (T_misc, no measured constant):
- Prover: about 2^k BLAKE3 calls per repetition, at most 2^12 for any RFC-0026-sized
  check.
- Verifier: one PoW call per repetition.
- Proof: +8 bytes per repetition, plus the Policy 2 multiplicity certificate and
  opening sizes of A14.

Controls: NC-0814 (a nonce failing the predicate, `GrindMismatch`), NC-0815 (a k−1
prover's nonce, `GrindMismatch`), NC-0816 (another valid nonce, absorbed, so β and α
change, `RoundSumMismatch`) and NC-0817 (the statement over Policy 1 originals,
`CertificateContext`). All four run through the actual A5 consumer.
Python parity: `research/fs-pcs/check_lu_grind.py` (bit table, and four standard
wires from the unchanged independent A5 producer of `lookup_corpus.py`, including
r = 2 with the second nonce at +8).

Admission: A8 makes the LU rounds meet (C1). It admits no profile level. A composed
standard proof also needs (C1) on every non-grinding round, plus (C2) and (C3); E8-05's
generator checks these. Until E8-05, `Descriptor::standard`, the standard path of
`resolve_pcs` and every Policy 2 source constructor (`from_bytes` included) exist only
under the Cargo feature `standard-unproven`. Only tests and negative controls enable it,
and the native gate checks that stele-cli, stele-prover and stele-verifier build
without it (ADR-108).

Affected tasks: E12-24 (implements A8), E8-05 (the generator enumerates these
rounds with their k), E16-30.
