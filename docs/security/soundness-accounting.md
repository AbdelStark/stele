# Soundness accounting (generated per proof config by `stele-verifier::accounting`; this file is the human-readable spec)

Total error ε = Σ SC + Σ RLC + Σ LU + Σ PCS + Σ MASK + FS + H (RFC-0012 §4). Profile bound: standard 2⁻¹⁰⁰, treaty 2⁻¹²⁸.

| Line | Instance count driver | Formula | Proven? |
|---|---|---|---|
| SC | stacked reductions per stage (≈ 10²/proof) | `m·δ/|K|` | yes (Schwartz–Zippel) |
| RLC | RLC batch reductions | `t/|K|` | yes |
| LU | one per (table, challenge pair) | `(N+|T|)/|K|`, squared with double challenge | yes (Haböck 2022) |
| PCS | one per opening (R_stack, 7–9 weight types, multiplicities, aux) | `ε_gap(ρ,δ)+(1−δ)^q+ε_Merkle` | treaty: proven only (BCIKS20, DP23/24, Khatam) |
| MASK | per masked instance | `≤ 1/|K|` | yes |
| FS | adaptive queries `Q` + grinding | ROM bound | assumption A2 |
| H | hash collisions | `Q²/2²⁵⁶` | assumption A1 |

Illustrative treaty budget for W4 appears in RFC-0012 §5; the generator must reproduce it. The gate
`scripts/gates/soundness-accounting.sh` diffs the generator's instance enumeration against the transcript labels actually
used by the prover (every `challenge(label)` call must map to a ledger line).

## Transcript label mapping (RFC-0012 A1)

The initial challenge label `stele/v0.1/sumcheck/challenge` maps to SC, once per
round in each consuming sumcheck; absorption labels introduce no random challenge.
QM31/OM31 denominators are exactly p^4/p^8. A1's conditional uniformity argument
adds no sampling-error line; exhaustion aborts and cannot certify a statement.
FS/H still cover all adversary queries and grinding. The gate compares the validated
`stele-hash` registry producer with [the canonical inventory](transcript-labels.json)
and runs the registry and transcript primitive unit tests. NC-0801 rejects a duplicated label at that same
production validator. Unimplemented protocol crates retain their scaffold guards.
Registry validation alone does not establish per-instance accounting or a profile
budget; the sumcheck consumer is checked separately below.
Q12 (RFC-0019) tracks the missing concrete FS theorem/query convention and the
incompatible illustrative H budget. No profile can be certified from placeholders.
Q29 and Draft RFC-0013 A1 additionally track the missing joint-view privacy and
mask-lifetime construction. The MASK placeholder above is not an instantiated
ZK theorem: an accounting record or mask-presence check cannot establish hiding.
Soundness losses, statistical privacy errors and mask-generation assumptions
must be derived separately for the eventual protocol. No production label or
accounting record is added by the privacy study.

The gate also runs A2's wrapper-feature permutation KATs. This unused permutation
adds no challenge or ledger line. Q14 must resolve the wrapper hash/transcript
mode and its separate budget before E14-01 consumes it. Native A1 is unchanged.

RFC-0006 A1 specifies the SC record: instance id, m, degree bound δ, field degree d,
and exact numerator m*δ over symbolic p^d. Its [interactive obligation](../../formal/sumcheck.md)
bounds passing a false initial sum together with true final evaluations; every
emitted evaluation still needs a consumer. The gate executes the actual Rust
prover/public verifier and independent Python verifier over the shared corpus.
It compares emitted SC records to verifier-owned descriptors and derived-point
lengths. NC-0200/0201/0205/0800/0802 exercise the actual reduction/consumer and
transcript schedule. Full inference enumeration remains E8-05; these finite checks
do not discharge Q12 or certify a profile.

RFC-0012 A3 fixes Merkle authentication bytes without adding a challenge or an
algebraic loss. Its binding argument is conditional on BLAKE3 collision resistance;
PCS ε_Merkle/H still require Q12's concrete global query accounting. Membership
alone does not certify codeword validity, canonical field encodings, unopened
subtrees or a profile budget. NC-0602 now checks both leaf kinds through actual construction/authentication;
this supplies membership-binding evidence, not a PCS or hash-budget certificate.

RFC-0006 A2 / RFC-0012 A4 now have both batching consumers: one BatchCoefficient
challenge maps to RLC t/p^d and shared rounds to SC M D/p^d (D=2 for claim mode).
Those eight label meanings are unchanged; A3 extends the registry below. Gates check 42 instance and six claim byte/
record cases, 10^4 coefficient evaluations per field, and actual two-mode controls.
The [interactive obligation](../../formal/batching.md) remains conditional on true
final evaluations. The 276-case shared Rust/Python corpus checks exact decisions, every returned obligation,
and SC/RLC records against descriptors. E3-02 has [both-field CPU baseline ledgers](../../bench/README.md#batching-e3-02);
Q12 still blocks certification. Catalog coverage is thirteen controls, not a full claim graph.

RFC-0006 A3 / RFC-0012 A5 now have a production zerocheck consumer. With j=m-k
and D=δ*(2^k-1), the three ordered SC phases record j (ZeroWeight), D (optional
skip Sumcheck), and j*δ (tail Sumcheck), over p^d. The twelve-label registry and
canonical inventory include its four labels. The [interactive obligation](../../formal/zerocheck.md)
remains conditional on all original slice claims. Both gates check 130 actual
Rust/Python byte/claim/record cases against descriptors and transcript continuation,
plus NC-0207..0209 and the ZeroFinal extension of NC-0802. Numerator, final-label
and public-consumer bypass mutants fail the gate. The reduction alone does not
accept a statement; the public adapter consumes every original slice claim.
The shared 314-case Rust/Python corpus additionally compares exact public-verifier
decisions, every original claim, phased SC records and the next challenge. Gate
regressions reject changed corpus expectations, omitted claims and wrong records.
Both gates also require 1,000 seeded direct-reference cases per degree and field,
including every eligible (m,k) through m=4, maximum skip with a tail at m=5,
and public claim consumption.
E3-03 has [both-field complete-cost/memory ledgers](../../bench/README.md#zerocheck-e3-03);
performance evidence does not strengthen the conditional algebraic bound. Q12 remains open; these gates do not certify a profile.

RFC-0006 A5's Small strategy retains the A1 transcript, final obligations and
SC m*δ/p^d record without new challenges or registry entries. Both gates require
QM31/OM31 directed proof parity, transcript continuation and the actual NC-0204
original-value rejection. Typed i16/u16 storage is an optimization eligibility
contract, not a range proof. Both gates additionally require 1,000 seeded cases per
degree and field against direct original-MLE evaluation and Dense, with all eligible
(m,k) through m=4 and k=4 with a tail at m=5. These compare the full proof, final
claims, SC record and continuation. A missing field test fails the gate. The shared
Rust reference uses production field/eq/transcript/engine primitives. The shared
302-case small-value corpus additionally compares the actual Rust and independent
Python A1 public decisions, every final claim and SC record. Its 76 honest chains
require actual Small prover bytes followed by an A1 continuation. Corrupted rounds,
proof lengths, unused finals and truncated originals yield 226 exact rejections.
Both gates check regeneration, checked adapter narrowing and actual prover parity;
regressions reject corpus drift, broken adapter selection and missing claims.
E3-04 now has [both-field complete-cost/memory ledgers](../../bench/README.md#small-value-pipeline-e3-04),
including consumer-dominated pipeline peaks and all losses. Performance evidence
does not change the SC bound; these finite checks certify no profile.

RFC-0010 A2's circle map has a deterministic distance lower bound N-k for k>=2,
and N for a constant message. This is not a PCS proximity-gap or profile bound.
Its encoder contract adds no transcript label, challenge or implemented loss line.
The CPU map now has direct-reference and Python-vector checks under E4-02, plus
the full input-size cost/memory ledger at both rates. A1's parameter provenance
and the actual PCS consumer/accounting tasks remain open. The code identity alone
cannot admit a profile or certify codeword validity of a Merkle commitment.

RFC-0006 A6's streaming contract retains A1's m*delta/p^d record, messages and
all original final consumers. No challenge, label or implemented loss changes.
Its source/layout/capacity studies establish neither production NC-0210 nor
profile security. The production strategy/file/control gates below do not resolve independent
streaming corpus and complete pipeline ledger requirements; Q12 is unchanged.

The A6 caller-buffer engine reuses A1's round/final checks and original public
consumer, without changing any loss line. Both accounting and control gates
require 1,000 Dense/buffered cases per degree and field, full proof/continuation
parity, unchanged caller capacities and typed preflight/false-sum/unused-final
rejections. Independent A1 corpus and digest checks still cover the shared
encoders/interpolator. This engine alone is not the Streaming strategy; complete source capacity and
pipeline memory/cost evidence remain separate delivery obligations.

The A6 generic source/arena strategy now preserves A1 proofs and original claims
in both fields. Gates require 1,000 cases per degree/field, canonical tail order,
source visit/error checks, workspace capacity limits and cached-instance rejection
including m=0. Its bound remains the same SC line. A generic source is not an
authenticated consumer. Independent streaming corpus decisions and complete
preparation/consumer memory ledgers are still required.

The opt-in std file adapter validates canonical limbs, exact lengths and EOF while
retaining read-only handles. Bounded preparation preserves originals and rejects
existing destinations. Both gates execute its real file tests and NC-0210 in both
fields: one unused source record changes one real-prover final, through ProverHook,
and the unchanged original consumer rejects ClaimMismatch. No new loss or trust in
source metadata is introduced. These checks do not certify a process-memory bound.

The shared streaming corpus adds 420 independently generated Python/Rust A1
decisions: 108 honest chains use actual Rust preparation/FileSource/Streaming
proofs and an A1 continuation; 312 tampered shapes, rounds, unused finals and
original lengths require exact rejection. Every claim, SC record and canonical
payload is compared. Actual source I/O receipts prevent a Dense-only adapter from
passing. Both gates check regeneration and the adapter; mutants corrupt the
fixture expectation or bypass Streaming. Complete pipeline ledgers remain open.

Q31 / Draft RFC-0008 A2 and RFC-0012 A8 identify another uninstantiated LU
hypothesis: ordinary unit multiplicities need a selected-count bound below the
field characteristic. QM31/OM31 share M31's characteristic. The exact p-copy
counterexample has zero rational difference even for invalid values, so no
extension-size root bound or squaring can justify it. Actual LU admission also
needs nonzero bound denominators, selector/padding, tuple compression and full
consumer/composition accounting. The [research note](../../formal/logup-characteristic.md)
changes no production record or challenge and supplies no profile admission.

The [Q31 fraction candidate](../../formal/fraction-reduction.md) proposes these
research-local lines per depth-m tree (denominator |K|): lookup/gamma has m
degree-one combinations; lookup/fold has m degree-one child folds; enclosed A1
sumcheck/challenge has 3m(m-1)/2. Its selected-product leaf has another 3m under
A1. Each tree/repetition adds its own terms, separately from the identity bound
and actual source/PCS/FS losses. Full labels have prefix stele/v0.1/. This does
not add labels to the production registry or grant a native LU/profile record.

The [whole Q31 candidate](../../formal/lookup-consumers.md) draws r*h lookup/unit,
r lookup/beta and r lookup/alpha after the stated source/unit/multiplicity phases.
These are jointly charged to the unit theorem's e^r. It separately adds
r*[F(m)+F(k)+3m]/|K| for both depth-m/k trees and the selected-product leaf, with
F(n)=3n(n-1)/2+2n. Actual transcript events are checked against these counts.
Full revealing openings add exact evaluation conditional on actual Merkle binding;
binding and FS/H still need Q12. This adds no production registry or profile.

RFC-0008 A3 / RFC-0012 A9 now fix the conditional native fraction contract.
Its Gamma/Fold RLC and scoped A1 SC terms are required with the actual engine.
Canonical types/codecs add no draw or production registry entry. Native original
consumers, controls and full enumeration remain required; A2/A8 and Q12 stay open.

The native RFC-0008 A3 tree now registers Fraction/Layer absorbs and Gamma/Fold
RLC draws from A9. Its actual prover/verifier return a tree-scoped record with
Gamma=m, Fold=m and ordered A1 records (id=k,m=k,degree=3,numerator=3k).
The gate compares both fields' proof bytes, every original claim, all record
fields and transcript continuation against Python, and runs actual public
consumers plus NC-0406..0408. This accounts for F(m)/|K| conditionally; selected
products, full lookup identity, private source/PCS, ZK and FS/H remain separate.
The unused Leaf label remains reserved, not registered by this tree-only change.

The native selected-product leaf now registers the reserved Leaf absorb and
uses A1's existing m Sumcheck draws, contributing 3m/|K|. LeafReduction retains
tree identity and the leaf-phase SC record separately from the tree's levels.
The shared Python/native corpus checks full proof bytes, original ids/claims,
record fields and continuation; real NC-0408..0410 consume Eq, public selector
and every original column. Initial p=sigma_tilde(r) has a real upstream tree
mutation control. This remains conditional arithmetic, without a complete
lookup/private source/PCS/ZK/FS admission or measured c_lu.

Actual fraction transcript controls now replay Gamma before Fraction/Layer and
Fold before Final (NC-0411), and omit tree/selected-product A1 Final before a
following real sumcheck (NC-0802 extension). Each first compares exact-order
replay with the native prover, then applies one replacement through ProverHook
and requires the unchanged real verifier's catalog rejection in both fields.
The accounting gate requires both named controls. No production draw, loss,
label, FS theorem, profile admission or measured constant changes.

The shared conditional fraction decision corpus now has 162 cases across QM31
and OM31: 28 honest reductions and 134 declared rejections. Both adapters run
the actual public consumers; accepted cases additionally reprove and compare
proofs, all original claims, tree/phase-scoped SC/RLC records and continuation.
Malformed bytes, changed roots/rounds/originals, zero-coefficient finals and
root poles require their stated errors and export no partial result. The gate
regenerates the corpus and checks every decision; regressions reject a missing
case or Fold accounting omission. This adds no soundness loss or full lookup,
PCS, private consumer, ZK, FS or benchmark admission. E3-07a primitive runtime
and memory ledgers remain required.

The [E3-07a primitive ledgers](../../bench/README.md#conditional-fraction-primitives-e3-07a)
now retain scoped native records for every measured public tree/selected-product
operation in both fields. Preparation, complete original consumption and native
process peaks are charged. These measurements change no random loss, label,
source/PCS/FS hypothesis or profile admission; exact-head CI and merges remain due.

Q20's [private selection study](../../research/stacked-gkr/PRIVATE-SELECTION.md)
adds research-only conditional A1 records: with a row bits and M the least power
of two >=max(1,k category bits), one SC(a,2) and M-1 SC(a,3) records contribute
`a*(3M-1)/|K|`. There are a*M existing-kind Sumcheck draws, no extra RLC draw,
and two candidate Evaluation/Originals absorbs. All child/original obligations
remain; even zero-coefficient originals are checked by the reference consumer.
This is not production registry/profile admission, source/bit/range/PCS binding,
FS/H accounting or ZK. Those additional consumers require their own losses;
the unmasked prototype and public oracle fixture do not discharge them.

The [weighted continuation](../../research/stacked-gkr/WEIGHTED-PRIVATE-SELECTION.md)
replaces the candidate Evaluation absorb with Weighted, binding full layout,
ordered source axes, category axis, source id, selectors, query and value.
Originals and all A1 schedules remain; multi-axis padding and public weights add
no challenge or random loss. Conditional records still total a*M draws and
a*(3M-1)/|K|. Source-scoped originals, including zero-weight cases, require every
real consumer. This remains unmasked research, with no production or ZK credit.

Q20's [private-stage composition](../../research/stacked-gkr/PRIVATE-STAGE.md)
adds the actual stage SC(m,delta) before weighted selection: PrivateStack binds
expected metadata, stage Final precedes Weighted, and every original remains.
There are m+a*M existing Sumcheck draws, conditional numerator
m*delta+a*(3M-1) over |K| and no new RLC draw. Stage/selection records stay scoped;
aligned 65-id blocks separate their actual instance ids, with pre-absorb overflow
checks. Full plan/tensor identity validation, source/bit/range/PCS, FS/H and joint ZK remain
unresolved. This research wrapper adds no accepted registry or profile bound.

Q20's [bit-source candidate](../../research/stacked-gkr/SELECTION-SOURCE.md) uses
two no-skip A3 relations of degrees 3 and 2 over D variables; all phase records
give numerator 7D. For C<2^k it adds a degree-2 A3 relation over a source variables
and k degree-3 A1 nodes: 3a(k+1). Draw counts are 4D, plus a(k+2) for that branch;
there is no extra RLC/skip draw. Source precedes all ZeroWeight draws. Every
original F/bit claim still requires its actual opening; stage/selection, PCS or
opening batching, FS/H and joint ZK are additional. This admits no format/profile.

Q20's [two-bit source](../../research/stacked-gkr/PAIRED-SOURCE.md) retains that
bit-core numerator with D=Db, adds 3a when k<2 for the unused low bit,
and 4*sum(m_i) for actual source resolvers. There is no separate membership
proof: the bit core and P=2H+L establish it through the actual resolvers.
Here m_i is the derived general/plane-view dimension, at most Dp; each range
or selection bit resolver has m_i=a. Draws are the bit core's draws plus
2a when k<2, and sum(m_i). The PairedSource frame precedes all of them; no RLC
or new challenge kind is used. Stage selection resolvers add 4ak and ak draws.
All original symbol finals require actual openings. PCS/batching, FS/H and joint
ZK losses remain additional; payload reduction is no proof/profile admission.

Q26/Q31's [capped scalar range consumer](../../research/cqis-bounds/CAPPED-RANGE.md)
uses the unchanged revealing Q31 lookup with m=b=a+3, c=1, t=256 and r in
{1,2}. The static selected count 2^(a+3)<=32768<p permits one ordinary unit and
no preliminary Unit draws. Its identity numerator is 2^(a+3)+255, raised to r after division by
|K| under the existing conditional theorem. Its separate reduction numerator is
r*[F(a+3)+F(8)+3(a+3)], F(n)=3n(n-1)/2+2n. It then invokes four k=0 A3 relations
with (m,delta)=(a,1),(a+2,1),(a+2,2),(a,1). Their ordered phase records sum to
9a+10, with 4a+4 ZeroWeight and 4a+4 Sumcheck draws and no skip draw. This A3
loss is added, not squared. The expected caps/source/table, all original/auxiliary
roots and completed lookup state precede these draws; every final is absorbed.
Twelve A3 and 2r lookup claims reach actual full-vector consumers. Tests compare
all records, draw counts and final states. Exact consumption adds no algebraic
loss conditional on the bound originals. Merkle binding, FS/H, private source
composition and joint ZK remain separate; no production profile or label is added.

Q26/Q31's [exact wide-word range consumer](../../research/cqis-bounds/WIDE-RANGE.md)
uses the same Q31 lookup with a=log2(N), b=log2(B), m=a+b+1, one ordinary unit,
c=1, t=256 and r in {1,2}. Expected caps below 2^160 determine B<=32 and
N<=4096, so the static count 2BN<=262144<p needs no preliminary Unit draws.
The conditional identity term is [(2BN+255)/|K|]^r; the separate lookup reduction
is r*[F(m)+F(8)+3m]/|K|, F(n)=3n(n-1)/2+2n. SourceCopy, CapRelation,
CarryBoolean and TerminalCarry invoke k=0 A3 with (dimension,degree)
(a+b,1),(a+b,1),(a+b,2),(a,1). Their twelve ordered records add (9a+7b)/|K|,
with 4a+3b ZeroWeight and 4a+3b Sumcheck draws, no skip draw. This term is
added, not squared. Nine A3 claims and 2r lookup claims reach actual revealing
original/public/view consumers. Expected caps/source/table, source/byte/carry
roots and completed lookup state precede A3 draws; all finals are absorbed.
No wide integer is embedded in the field: only byte columns use integer
faithfulness, followed by integer telescoping. Exact full-vector consumption
adds no algebraic loss conditional on binding. Hash binding, FS/H, private
source composition and joint ZK remain additional. No profile or label is added.

Q26/Q31's [limb input source consumer](../../research/cqis-bounds/LIMB-SOURCE.md)
derives N=2^a input rows per side and B=2^b byte planes from the expected limb
schema. Whole-word rows are 2N, so that nested wide consumer contributes
9(a+1)+7b in A3 numerator and uses Q31 dimension m_w=a+b+2. Nibbles additionally
have an exact cap15 consumer over 4BN original digits, contributing 9(a+b+2)
in A3 numerator and using Q31 dimension m_n=a+b+3. The byte/nibble packing
relation is degree1, k=0, dimension a+b+1, adding 2(a+b+1). Total A3 loss is
(11a+11+9b)/|K| for bytes or (20a+18b+29)/|K| for nibbles. For each used
lookup independently retain [(2^m+255)/|K|]^r and r*[F(m)+F(8)+3m]/|K|;
add these terms, never square the other reductions. All static selected counts
remain below p, and no Unit draws occur. Total ZeroWeight and Sumcheck draws
are each 5a+4b+5 for bytes or 9a+8b+13 for nibbles. Packing emits two/three
actual claims; each nested wide proof consumes nine A3 and 2r lookup claims.
Expected schema/source, source/word roots and completed nested states precede
packing challenges; every final is absorbed. Nibble ranges precede integer
packing faithfulness, not vice versa. Exact full-vector consumers add no algebraic
loss conditional on binding. Hash binding, FS/H, model source composition and
joint ZK remain separate. No production profile, commitment category or label.

Q26/Q31's [consumed limb product](../../research/cqis-bounds/LIMB-PRODUCT.md)
retains the complete limb-source and two capped-scalar range accounts. Write
N=2^a rows per side, P=2^h digit planes, K real result columns and S=2^g>=K+1.
The two scalar consumers each add 9g+10 in A3 numerator and one Q31 lookup
with m=g+3. All their lookup identities/reductions remain separate from the input
consumer's terms. After those roots/range states, one fresh Sumcheck draw rho
compresses the integer-column residual polynomial. Its degree is at most K-1,
conditional on the actual range statements: excess source/output/carry planes
vanish and each real coefficient is faithful under the recomputed certificate.
Add (K-1)/|Kfield|, including zero when K=1; retain the draw in that case.
Three degree2 A1 invocations have dimensions a,h,h and add (2a+4h)/|Kfield|.
Their additional draws total 1+a+2h, with no ZeroWeight or new label. Every A1
Final is absorbed. Two main virtual claims reach the digit sumchecks; their
two public and two actual original-source claims are consumed at the derived
points, preserving the same row point on both sides. No random-expression
inverse or fixed-radix substitution is used. Add these losses, do not square
them with lookup repetitions. Hash binding, FS/H, private source composition
and joint ZK remain separate; no native profile or commitment format is admitted.

Q26/Q31's [signed byte-source consumer](../../research/cqis-bounds/SIGNED-SOURCE.md)
has N=2^a rows and B=2^b bytes, B in {1,2,4}. TopBit and Terminal each use
degree1 A3 of dimension a; Positive, Negative, CarryBoolean and CarryInactive
each use degree2 A3 of dimension a+b. Their added loss is (16a+12b)/|K|,
with 6a+4b draws each of ZeroWeight and Sumcheck, all Finals absorbed. The two
raw/magnitude wide ranges add 2(9a+7b); the sign/high7 range adds 9(a+1).
Total A3 is (43a+26b+9)/|K|, and total A3 draws of each label are 18a+10b+4.
The three Q31 dimensions are a+b+1, a+b+1, a+2. For each separately add
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|. No reduction term is squared.
Static selected counts 2BN<=16384 and 4N<=8192 are below p; no Unit draws.
Four roots and three completed range states precede the six new A3 invocations.
All 16 signed claims, nine A3 claims per range and 2r lookup claims per range
are consumed against their actual originals or deterministic views, including
inactive branches. Static per-byte sides <=511 make integer telescoping faithful;
top-bit/sign ranges make the representation unique. Full-vector binding, FS/H,
private model-source routing and joint ZK remain separate. No new label or profile.

Q26/Q31's [scalar Requant consumer](../../research/cqis-bounds/REQUANT-CONSUMER.md)
retains two actual signed sources, one wide remainder range and four byte product
consumers. There are 19 separately repeated lookup identities. Their dimensions,
in order, are 3,3,2 for input; bo+1,bo+1,2 for output; br+1 for remainder; and
aj+bj+2,gj+3,gj+3 for each product j. Here bo=log2(output bytes), br=log2(remainder
byte planes), aj=0,1,0,1, bj=log2(product input byte planes), gj=log2(result/carry
size). Retain every [(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K| separately. Product
identity losses sum to sum_j(Kj-1)/|K| and their A1 losses to sum_j(2aj+4bj)/|K|.
All fresh rho and nested range/A3/A1 draws remain. Final sign A3 has degree2,
dimension bo, k=0 and adds 3bo/|K|, with bo draws each of ZeroWeight/Sumcheck.
Total A3 numerator, including sign and all nested ranges, is
216+29bo+7br+sum_j(9bj+18gj). Thirteen expected/derived roots and seven completed
verified states precede final sign A3; all three finals have actual consumers,
including zero quotient. Exact source-root and full-byte equality consumers
introduce no algebraic loss conditional on binding. No reduction loss is squared
by lookup repetition. Hash binding, FS/H, native/model ownership, stacking and
joint private PCS/ZK remain separate; no new label or profile is admitted.

Q26/Q31's [attained-magnitude consumer](../../research/cqis-bounds/ATTAINED-MAGNITUDE.md)
has N=2^a padded elements and B=2^b signed bytes, B in {2,4}. Four parent k=0
A3 invocations have (dimension,degree) (a+b,1), (a+b,2), (a,1), (a+b,2).
They add (10a+8b)/|K| and draw 4a+3b each of ZeroWeight/Sumcheck. Degree1 A1
sum E=1 adds a/|K| and a Sumcheck draws separately. Including signed source and
maximum/gap/indicator ranges, total A3 numerator is 71a+48b+9; total A3/A1
draws are 30a+19b+4 ZeroWeight and 31a+19b+4 Sumcheck. Six lookup dimensions
are a+b+1, a+b+1, a+2, b+1, a+b+1, a+1. For each retain
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K| separately; no reduction loss is
squared. Static selected counts are below p; no Unit draws. Six roots and four
verified child states precede the parent challenges. Nine parent A3 claims and
one A1 claim have actual full-vector/view consumers, including inactive factors;
all Finals are absorbed. Byte sides <=511 and N<=2048 make integer columns
and the bit sum faithful. Padding has cap zero and a masked maximum broadcast.
Binding, FS/H, committed index/model ownership, stacking and joint private PCS/ZK
remain additional; no production commitment category, label or profile is admitted.

Q26/Q31's [dynamic-scale consumer](../../research/cqis-bounds/DYNAMIC-SCALE.md)
retains the complete attained-magnitude account. With N=2^a and B=2^b, it adds
three wide ranges of (word dimension,byte dimension) (0,b), (0,0), (b,0),
contributing 7b,0,9b in A3 numerator. Their lookup dimensions are b+1,1,b+1;
retain each [(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K| separately alongside
the six inherited identities. Two degree1 k=0 A3 invocations have dimensions
b and0, adding 2b/|K| and b draws each of ZeroWeight/Sumcheck. The terminal
dimension0 invocation retains its Instance, Final and actual claim. Total A3
numerator is71a+66b+9, with the inherited A1 numerator a separate. Total A3/A1
draws, excluding lookup schedules, are30a+27b+4 ZeroWeight and31a+27b+4 Sumcheck.
Five roots and four verified child states precede parent challenges. Six parent
final claims and every nested claim have actual consumers; all Finals are absorbed.
Biased carries T=C+1 lie in[0,127]; faithful byte sides are bounded by32893,
with public T0=TB=1. Exact slack<=126 makes the ceiling unique, including zero.
No reduction loss is squared and no new label/profile is admitted. Binding,
FS/H, committed-index/model ownership, native stacking and private composition
remain additional.

Q26/Q31's [dynamic row-code consumer](../../research/cqis-bounds/ROW-CODE.md)
retains the complete dynamic-scale account. Let Nrows=2^a, B=2^b original bytes
and P=2^c division planes; the closed schema derives c=2 for both kinds. Seven
parent k=0 A3 invocations have (dimension,degree) (0,2),(0,2),(a,1),(a,1),
(a+c,2),(a,1),(a,2). They add (12a+3c)/|K| and 5a+c draws of each label,
with22 actual finals; zero dimensions retain their records and Finals. Including
all children, A3 numerator is171a+87b+12c+25 and inherited A1 numerator a is
separate. Total A3/A1 draws excluding lookup schedules are73a+36b+5c+11
ZeroWeight and74a+36b+5c+11 Sumcheck. Preserve19 lookup identities: dynamic
scale's nine, signed output dimensions a+1,a+1,a+2, then quotient/remainder/gap/
zero-gap/nonzero/predecessor/carry dimensions a+1,a+b+1,a+b+1,a+1,1,b+1,a+c+2.
Each separately contributes [(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|; no
reduction is squared. Static selected counts stay below p; no Unit draws.
Ten roots and nine fully verified states precede parent challenges. Actual source
packing/broadcast/masking views consume every final at its emitted point, even
for zero coefficients. Biased carries T=C+3 in[0,258] and T0=TP=3 give integer
column sides<=66813. Remainder/zero/flag identities have static bounds below p/2;
actual ranges make strict division and zero semantics faithful. All Finals are
absorbed. Binding, FS/H, physical/model ownership, native stacking and joint
private composition remain additional; no production label/profile/cut is admitted.

Q26/Q31's [static row-code consumer](../../research/cqis-bounds/STATIC-ROW-CODE.md)
uses Nrows=2^a, input bytes B=2^b, remainder bytes Br=2^br and P=2^c=max(B,Br).
Three parent k=0 A3 invocations have (dimension,degree) (a+c,2),(a,1),(a,2),
adding(8a+3c)/|K| and3a+c draws each of ZeroWeight/Sumcheck, with10 actual
finals. Total A3 numerator is121a+26b+7br+12c+25; there is no A1. Full A3
draws of each label, excluding lookup schedules, are51a+10b+3br+5c+11. Nine
lookup dimensions are a+b+1,a+b+1,a+2; a+1,a+1,a+2; a+1; a+br+1; a+c+2.
Each separately contributes[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|; no
reduction is squared. Public scale-root equality adds no algebraic loss. Seven
roots and five verified child states precede parent challenges. Every final
has an actual source/public/view consumer at its emitted point, even for zero
factors. All Finals remain absorbed. Static byte sides<=66813 and actual
T=C+3 in[0,258] with T0=TP=3 yield faithful integer division; actual Q<=127
and R<=2*S-1 imply the closed gated domain afterward. NP<=4096 keeps counts
below p; no Unit draws. Binding, FS/H, physical/model ownership, native stacking
and private composition remain additional; no production label/profile/cut.

Q26/Q31's [gated-product consumer](../../research/cqis-bounds/GATED-CONSUMER.md)
has N=2^a elements. Three parent k=0 A3 invocations have (dimension,degree)
(a+2,2),(a,1),(a+2,3), adding(9a+14)/|K| and3a+4 draws each of
ZeroWeight/Sumcheck with12 actual finals. Three signed-source children and
the carry range give total A3 numerator147a+163, full label counts61a+64 each,
excluding lookup schedules. No A1. Ten lookup dimensions are a+2,a+2,a+2
twice, then a+3,a+3,a+2, then a+3. Each separately contributes
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|; no reduction is squared. Seven
roots and four verified child states precede parent challenges; all Finals and
actual consumers remain, including zero factors. Actual signed16 magnitudes
give high bytes<=128; actual C<=255 yields static column sides<=65535. Integer
product then implies output magnitude<=2^30; no circular bound. C0=C4=0 and
actual signs close multiplication and canonical zero. N<=1024 keeps lookup
counts below p; no Unit draws. Binding, FS/H, SiLU membership, physical/model
ownership, native stacking and private composition remain separate. No admitted
production cut, label, profile or original control credit.

Q26/Q31's [SiLU consumer](../../research/cqis-bounds/SILU-CONSUMER.md) has N=2^a
rows and the complete two-column table T=65536. Two signed16 children add
A3 numerator86a+70, and36a+28 draws of each A3 label, excluding lookup schedules.
Six range lookups each contribute[(2^(a+2)+255)/|K|]^r and
r[F(a+2)+F(8)+3(a+2)]/|K|. Functional membership adds
[(2^a+131071)/|K|]^r and r[F(a)+F(16)+3a]/|K|, F(m)=3m(m-1)/2+2m,
F(16)=392. No reduction is squared. Functional beta/alpha draws each r,
gamma/fold each r(a+16), Sumcheck r[a(a-1)/2+120+a]; no Unit draws.
All multiplicity roots precede every beta/alpha. Every original input, output
and multiplicity claim is consumed at its emitted point, including zero rows.
Exact joins derive field columns from verified raw byte planes and sign bits;
they add no algebraic loss conditional on binding. The parent adds no challenge.
Its final transcript seed binds expected function/representation bytes, six roots
and three verified child states. Whole canonical table generation remains required;
a matching id or only queried rows cannot authorize supplied data. E>F rejects
the whole configuration even for a zero query. N<=2048 is a research capacity.
Binding, FS/H, physical/model ownership, native stacking and private composition
remain additional; no admitted profile, production cut or native control credit.

Q26/Q31's [RMSNorm statistic consumer](../../research/cqis-bounds/NORM-STATISTIC.md)
joins the same actual signed16 magnitude into both operand roles of one complete
sum-of-products consumer. With Nrows=2^a, signed A3 contributes43a+35; product
input whole-range/packing11a+20, and two dimension3 capped ranges74, for total
54a+129. Six lookup dimensions are a+2,a+2,a+2,a+3,6,6. Retain each separate
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|. Product polynomial identity adds
(C-1)/|K| for C result columns; its three A1s add(2a+4)/|K|. Neither term is
squared or multiplied by lookup repetitions. C=4,5,6 for dimensions1..3,
4..1023,1024..2048 respectively. Full ZeroWeight draws23a+55, Sumcheck24a+58,
excluding lookup schedules; the latter includes rho and all three A1s. Parent
draws none; its seed binds complete expected norm function bytes, four roots
and two verified child states. Both original operand/power claims retain their
actual consumers even at zero factors. Exact duplication adds no algebraic loss
conditional on binding. Enforced whole inputs/carries/boundaries give faithful
integer columns and derive S<=d*2^30 afterward; digit caps alone do not. All
high output padding remains ranged. Binding, FS/H, remaining norm roles, model
ownership and private composition remain additional; no native/profile credit.

Q26/Q31's [RMSNorm numerator consumer](../../research/cqis-bounds/NORM-NUMERATOR.md)
uses statistic bytes B_s=2^b_s, product planes B=2^b and output slots2^g.
The statistic range adds A3 7b_s; product input range/packing22+9b and output/
carry ranges18g+20, totaling7b_s+9b+18g+42. Four lookup dimensions are
b_s+1,b+3,g+3,g+3; retain each separate[(2^m+255)/|K|]^r and
r[F(m)+F(8)+3m]/|K|. Product identity adds(C-1)/|K| for C result columns,
and its three A1s add(2+4b)/|K|. These product losses are not squared or
repeated with lookup r. Full ZeroWeight draws3b_s+4b+8g+18 and Sumcheck
3b_s+6b+8g+20 exclude lookup schedules and include product rho/A1s. Parent
draws none; its final seed binds complete expected norm bytes, four roots and
two verified child states. The full eight-slot S root retains high zero padding
even with a four-byte range child. Actual S<=Smax precedes the exact configured
(S,U)/(ed,en) source join; all original/public product claims remain consumed,
including zero factors. Static integer columns establish N and its closed bound
afterward; generic result digit caps do not. Exact joins add no algebraic loss
conditional on binding. FS/H, remaining norm roles, physical/model ownership and
private composition remain additional; no admitted native/profile/cut credit.

Q26/Q31's [RMSNorm exponent consumer](../../research/cqis-bounds/NORM-EXPONENT.md)
uses a dimension6 one-byte range with fixed caps1 on33 indices and0 on31 pads.
Its A3 numerator is54. The dimension7 range lookup retains identity(383/|K|)^r
and reduction198r/|K|, using F(7)+F(8)+21=198. Parent degree2 A3s of
dimensions6,10 add18+30, so the total A3 numerator is102. One degree1 A1 of
dimension6 enforces sum1 and adds6/|K| separately, neither squared nor repeated
with lookup r. Parent ZeroWeight draws16 and Sumcheck22; full nonlookup draws
are40 and46. Lookup beta/alpha each draw r, gamma/fold each15r, Sumcheck56r;
there are no Unit draws. The parent seed binds complete expected norm bytes,
offset/factor/indicator roots and the verified range state before Exponent,
Factors, OneHot instances in order; each final remains absorbed. All six A3
original/public claims and the A1 original claim retain their actual points
and full-table consumers. Canonical fields, actual indicator caps and static
sum bound64<p establish a unique allowed index; the A3s then force offset and
every factor byte, including inactive/high slots. Public tables are derived
from the entire fixed index domain, never a supplied factor. Binding and FS/H
remain additional, as do scaled numerator/divisor, strict remainder, rsqrt,
outputs and physical/model/private ownership. No admitted profile or cut credit.

Q26/Q31's [RMSNorm scaled numerator consumer](../../research/cqis-bounds/NORM-SCALED.md)
uses one complete exponent child and the closed scaled limb product. With
product planes2^b and output slots2^g, exponent A3 contributes102 and product
input whole-range/packing9b+11 plus output/carry18g+20, totaling133+9b+18g.
Four separate lookup dimensions are7,b+2,g+3,g+3; retain each
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|. Exponent selection A1 adds6/|K|;
product identity(C-1)/|K| and product A1s4b/|K| remain separate, unsquared and
unrepeated with lookup r. Full nonlookup ZeroWeight draws53+4b+8g and Sumcheck
60+6b+8g include product rho and both plane A1s. Parent draws none; its final
seed binds complete expected norm bytes, five roots and two verified states.
All exponent originals/public claims and both original/product power claims
retain actual consumers, even at N=0. The entire8/16-slot numerator root is
reconstructed from actual product bytes and exact zero extension; excess product
bytes must be zero. Product input ranges enforce the exact Nmax bound, so no
redundant numerator range or whole-field lift is introduced. Static faithful
columns and zero carry boundaries establish A, retaining all16/32 output slots.
Exact source joins add no algebraic loss conditional on binding. FS/H, divisor,
normalized interval, strict remainder, rsqrt and model/private composition remain
additional; no admitted profile, native control or production cut credit.

Q26/Q31's [configured RMSNorm divisor consumer](../../research/cqis-bounds/NORM-DIVISOR.md)
retains one complete scaled child and adds a dimension10 degree2 A3. Its three
actual originals are the same verified indicator repeated across16 byte planes,
the independently bound divisor repeated across64 indices, and the full expected
P-derived public grid, with zero padding after33 valid indices. All three
emitted MLE claims retain their actual points and full-table consumers. This
adds30/|K|,10 ZeroWeight and10 Sumcheck draws, not a new lookup or product loss.
Total A3 numerator is163+9b+18g; full nonlookup draws63+4b+8g ZeroWeight and
70+6b+8g Sumcheck. Preserve separate lookup dimensions7,b+2,g+3,g+3 with each
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|, exponent A1 loss6/|K|,
product identity(C-1)/|K| and product A1 loss4b/|K|. Only the lookup identity
has its specified power r; no whole reduction loss is squared. Complete norm
bytes, all four expected roots and the verified child state seed the parent
before its A3 instance/weights/rounds/final. Exactly one allowed indicator and
canonical field equality force each divisor byte to its expected public value;
static Dmax<2^124 then holds without a whole-field integer lift. No independent
indicator/public table is accepted. Binding, FS/H, mantissa/strict remainder,
rsqrt/output and physical/model/private composition remain additional; no
admitted profile, production cut or native control credit.

Q26/Q31's [RMSNorm mantissa product consumer](../../research/cqis-bounds/NORM-MANTISSA-PRODUCT.md)
uses a scalar two-byte offset range with cap49151, contributing A3 numerator7.
The closed normal_product role with planes2^b and output slots2^g adds
9b+18g+31; total A3 numerator9b+18g+38. Four separate lookup dimensions
2,b+2,g+3,g+3 retain each[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|.
Product identity(C-1)/|K| and product A1 reduction4b/|K| remain separate,
unsquared and unrepeated by lookup r. Full nonlookup draws16+4b+8g ZeroWeight
and17+6b+8g Sumcheck include product rho and both plane A1s. Parent draws none;
its final seed binds complete expected norm bytes, five roots and two verified
states. Actual offset range precedes the exact affine M=16384+lo+256*hi view,
with static2*65535<p and canonical one-field encoding checked before hashing.
The full16-slot divisor root is reconstructed from actual right planes and
exact zero extension, and left planes derive only from verified M. Complete
whole-input/range/carry/polynomial and original/public consumers remain even
at D=0. Faithful integer product acceptance gives MD<=65535*Dmax afterward;
digit caps alone do not. Exact joins add no algebraic loss conditional on
binding. Positive/configured D, FS/H, A=MD+R, strict remainder, rsqrt/output
and model/private composition remain additional; no admitted profile/cut credit.

Q26/Q31's [RMSNorm decomposition consumer](../../research/cqis-bounds/NORM-SUM.md)
uses the count2 closed normal_sum role. For planes2^b, output slots2^g and
C result columns, complete inherited A3 numerator is9b+18g+42. Three separate
lookup dimensions b+3,g+3,g+3 retain each identity[(2^m+255)/|K|]^r and
reduction r[F(m)+F(8)+3m]/|K|. Product identity(C-1)/|K| and A1 reduction
(2+4b)/|K| remain separate and unrepeated by lookup r. Nonlookup draws are
18+4b+8g ZeroWeight and20+6b+8g Sumcheck, including rho and all three A1s.
The parent draws none; complete norm bytes, five roots and the verified child
state seed its final state. Actual left planes reconstruct the full external
MD/R roots; every right plane equals the fixed unit view. Actual output slots
reconstruct full A, with excess internal slots zero and exact zero extension.
All complete whole-input/packing/output/carry/polynomial and original/public
consumers stay. Integer A=MD+R follows after acceptance; generic MDmax bounds
do not supply strict R<D or upstream origins. Exact joins add no algebraic
loss conditional on binding. FS/H, strict comparison, reciprocal/output and
physical/model/private composition remain additional; no native profile credit.

Q26/Q31's [strict RMSNorm remainder](../../research/cqis-bounds/NORM-REMAINDER.md)
fully verifies scalar ranges with caps Dmax,Dmax-1,Dmax-1. Their widths are
derived independently:2^bD for D and2^bR for R/G. Inherited A3 numerator is
7bD+14bR; parent dimension4 degree2 carry Boolean contributes12, dimension0
terminal contributes0, and dimension4 degree1 columns contribute8. Total A3
numerator7bD+14bR+20. Three lookup dimensions bD+1,bR+1,bR+1 keep separate
identities[(2^m+255)/|K|]^r and reductions r[F(m)+F(8)+3m]/|K|; reductions
are not squared. Parent draws8 ZeroWeight and8 Sumcheck; full nonlookup counts
are3bD+6bR+8 of each. Complete expected norm bytes, two external roots, three
actual internal source roots, actual carry root and three verified range states
precede parent instances/weights/rounds/finals. All byte/shift/carry originals
retain actual emitted-point consumers. Static side bounds511 with2*511<p
justify the integer lift after range and Boolean acceptance. Fixed c0=1 and
c16=0 then give R+G+1=D, including strictness and positive D. Binding/FS and
upstream same-root composition remain separate; the four composed arithmetic
consumers still do not admit reciprocal/output or physical/model/private proof.

Q26/Q31's [RMSNorm reciprocal lookup](../../research/cqis-bounds/NORM-RSQRT.md)
has m=b=0, tuple arity2 and T=49152 valid rows. Its identity numerator is
1+2*T-1=98304, giving(98304/|K|)^r. Table-tree dimension16 contributes the
separate reduction392r/|K|; no A3 term or parent challenge is added. Every
repetition draws one beta and alpha,16 fraction gamma,16 fraction fold and120
Sumcheck challenges; no unit challenges. All multiplicities bind before every
beta/alpha; full expected table and actual source roots precede them. All3r
source/multiplicity claims and public table denominators retain their complete
consumers. Canonical65536-row generation preserves the16384 zero padding rows,
but only49152 distinct valid tuples enter membership. Fraction-tree padding is
neutral(0,1), not an admitted source tuple. Parent final state binds complete
expected norm function/representation bytes, canonical table identity, two roots
and verified lookup state. Binding/FS, upstream same-root normalized interval,
wide outputs and native/physical/model/private proof remain additional.

Q26/Q31's [same-exponent output factors](../../research/cqis-bounds/NORM-OUTPUT-FACTORS.md)
retain one complete paired A/D consumer and add a dimension12 degree2 A3,
contributing36/|K| and12 draws of each parent label. Total A3 numerator is
199+9b+18g. Inherited selection A1 loss6, product identity C-1 and product
A1 loss4b remain separate, as do the four lookup dimensions7,b+2,g+3,g+3
and their independently repeated identities/reductions. Full nonlookup draws
are75+4b+8g ZeroWeight and82+6b+8g Sumcheck, including product rho/A1s.
Complete expected norm bytes, five roots and fully verified paired state seed
the parent before weights/rounds/finals. The same actual one-hot indicator
forces every flag/byte to the complete expected-parameter public grid; bounds
B<=2^90,h<=2^89,L<=2^16 follow without whole-factor field lifts. All original
and public MLE consumers, inactive factors and high zero slots remain. Binding,
FS/H, normalized interval, actual J/signed products, output branches and native/
physical/model/private composition remain additional; no profile/cut credit.

Q26/Q31's [RMSNorm magnitude product](../../research/cqis-bounds/NORM-XY.md)
uses N=2^a padded elements, two complete signed16 sources and two whole ranges.
The signed children contribute A3 numerator86a+70, output9a+14 and carry9a+18.
One dimension a+2 degree2 parent A3 contributes3a+6, totaling107a+108 over|K|.
Six signed-range lookups retain dimension a+2 and output/carry dimension a+3.
For each separately retain identity((2^m+255)/|K|)^r and reduction
r*[F(m)+F(8)+3m]/|K| with F(m)=3m(m-1)/2+2m; reductions are not squared.
All lookup multiplicities bind before beta/alpha, and complete fraction/source/
public consumers remain. Full nonlookup draws are45a+44 of each A3 label;
the parent draws a+2 each and consumes all seven actual original views.
Complete expected norm bytes, three external roots, three auxiliary roots and
four verified child states seed the parent before its weights/rounds/finals.
Closed outgoing carry caps254,255,64,0 and whole source/output bounds make both
column sides at most65535 with2*65535<p. Binding/FS, actual xy*J, canonical
product sign, output branches and native/physical/model/private composition
remain additional. This1024-element revealing adapter adds no profile or cut.

The [range capacity continuation](../../research/cqis-bounds/RANGE-CAPACITY.md)
admits at most65536 caps with padded N*B<=131072. It preserves2BN<=262144<p
and m=a+b+1<=18, so the existing exact lookup identity/reduction formulas and
characteristic-safe unit remain. With a<=16,b<=5,a+b<=17, wide-range A3 loss
9a+7b is at most151/|K| and each nonlookup label has at most67 draws. These
replace the old domain maxima143 and63; actual per-instance accounting remains
exact. Old-domain encodings/challenges are unchanged. Signed count<=16384 gives
maximum signed32 A3 numerator663 with lookup dimensions17,17,16. Full-row xy
has a=14, A3 numerator1606, six dimension16 and two dimension17 lookups, and674
draws of each nonlookup label. Repetitions apply only to each lookup identity
and its separately linear reduction. Every original/public claim and carry
boundary remains consumed. Expected cap metadata can grow to1310720 bytes
and the terminal A3 view to65536 entries; the word-byte bound does not conceal
these increases. Binding/FS, other norm
roles and native/physical/model/private inference remain additional.

The [norm reciprocal-product study](../../research/cqis-bounds/NORM-PRODUCT.md)
uses N=2^a padded rows and five complete ranges with lookup dimensions
a+3,2,a+4,a+4,a+2. Each retains its own identity ((2^m+255)/|K|)^r and
reduction r*[F(m)+F(8)+3m]/|K|, F(m)=3m(m-1)/2+2m. Range A3 numerators
sum to 36a+76; the degree-two dimension a+3 parent adds 3a+9, giving
(39a+85)/|K|. Full nonlookup draws are 17a+36 of each A3 label. At a=14,
these are numerator 631, 274 draws per label and lookup dimensions 17,2,18,18,16.
No scalar-join challenge is added: actual verified J-8192 bytes reconstruct J
and its canonical-u32 root is compared with the expected rsqrt output root.
The parent absorbs expected norm bytes, three external roots, three auxiliary
roots and five verified child states before weights/rounds/finals. All seven
original views are consumed, including zero-hidden operands and both high
output planes. Closed carry caps 0,254,318,318,128,16,0 and whole xy/J/t ranges
give maximum column side 81663, with 2*81663<p. Runtime receipt checks remain
required. Binding/FS, full rsqrt membership, canonical sign/zero predicates,
output branches and native/physical/model/private composition are additional.

The [norm canonical-sign study](../../research/cqis-bounds/NORM-SIGN.md) retains
the complete xy consumer and adds two ranges, each with lookup dimension a+3,
for Boolean flags and bounded predecessors. Their A3 numerators are 9a+18 and
9a+16; parent predicate/sign A3 numerators are 3a+6 and 3a. Total A3 is
(131a+148)/|K|, with 55a+61 draws of each nonlookup label. Six lookup
dimensions are a+2 and four are a+3, each retaining its separate identity
((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|. At a=14, A3 is
1982/|K| and each nonlookup label has 831 draws. No challenge is added by
the exact sign-root reconstruction from the actual verified flag plane.
Expected norm bytes, four external roots, two auxiliary roots and all three
verified child states precede parent weights/rounds/finals. All nine parent
original claims are consumed. Whole m<=32768, k<=32767 and Boolean flags
bound predicate sides by 65536; sign sides are at most 2 and 3. All are
strictly below p/2. Expected zero caps retain padded flags/predecessors; there
is no quotient/output selector. Runtime receipts, binding/FS, configured
output branches and native/physical/model/private composition remain additional.

The [full-row statistic consumer](../../research/cqis-bounds/NORM-STATISTIC-FULL.md)
has signed-source A3 numerator43a+35 for N=2^a. The scalar S range has byte
width2^bs (bs2or3), and its carry vector pads to eight words of byte width2^bc
(bc0..2). Their A3 contribution is27+7(bs+bc), giving total
(43a+62+7(bs+bc))/|K|. Three degree-two A1 column sums add6a/|K| separately;
five dimension-zero tail instances add no draw or algebraic loss. Lookup
dimensions are a+2 three times, bs+1 and bc+4. Each retains its own identity
((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. A1/A3 losses are not squared with lookup repetitions.
Nonlookup draws are18a+26+3(bs+bc) ZeroWeight and21a+26+3(bs+bc) Sumcheck.
At full a14/bs3/bc2, A3=699, A1=84, ZeroWeight=293 and Sumcheck=335.
Five roots, three verified child states and complete expected norm bytes
precede parent instances. Each initial sum is derived from actual verified
S/carry bytes and absorbed before challenges; all four original byte claims
have independent consumers at emitted points. Whole bounds, zero endpoints
and closed column sides enforce integer lifting: maximum1073709311<p/2.
Exact S-root zero extension adds no challenge. Runtime receipts, binding/FS,
native/model/private composition and all remaining norm roles stay additional.

The [quotient-product consumer](../../research/cqis-bounds/NORM-QUOTIENT-PRODUCT.md)
has N=2^a rows and P=2^c padded columns. Let bd/bl/bh be byte-width exponents
for offset B-1 and low/high result ranges, h indicate an active high range,
and g count active four-plane carry families with exponents bg. All activity
comes from the closed expected certificate. Set X=1+bd+bl+h*bh+sum(bg).
Total A3 loss is[(21+9h+9g)*a+7X+18g+3c]/|K|; each nonlookup label has
(9+4h+4g)*a+3X+8g+c draws. Lookup dimensions are a+2, bd+1, a+bl+1,
a+bh+1 when h=1, and a+bg+3 for each active family. Each keeps its separate
identity ((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. No A3 term is squared with lookup repetitions.
At full a14/c4, bd4/bl3/bh3, h1/g4 and sum(bg)=3, A3 is1106/|K| and
each nonlookup label has484 draws; lookup dimensions are16,5,18,18,18,18,18,17.
Complete metadata, three external roots, all auxiliary roots and verified
range states precede parent weights/rounds/finals. All seven original views
have independent consumers at emitted points. Actual bounded offset bytes
reconstruct positive B and its expected16-slot root without a challenge.
Split result bounds imply digit caps only; whole q/B, faithful columns and
zero carry endpoints yield qd<=Zmax afterward. Maximum column side98047 is
below p/2. Original source/range consumers retain zero quotients and padding.
Runtime receipts, binding/FS, actual factor/branch authentication, remaining
output roles and native/model/private composition stay additional.

The [biased-sum consumer](../../research/cqis-bounds/NORM-BIAS.md) has
N=2^a rows and P=2^c padded columns. Let bh/bl/bu be byte-width exponents
for scalar bias and low/high result ranges, H indicate an active high range,
and g count active four-plane Boolean carry families. With
X=3+bh+bl+H*bu, total A3 loss is[(20+9H+9g)*a+7X+18g+2c]/|K|;
each nonlookup label has(9+4H+4g)*a+3X+8g+c draws. Lookup dimensions are
a+4, bh+1, a+bl+1, optional a+bu+1 and g instances of a+3. Each retains
its own identity ((2^m+255)/|K|)^r and reduction
r*[F(m)+F(8)+3m]/|K|, F(m)=3m(m-1)/2+2m. A3 is not squared with r.
At full a14/c4, bh4/bl3/bu2, H1/g3 and X12, A3 is930/|K| and each
nonlookup label has414 draws; lookup dimensions are18,5,18,17,17,17,17.
Complete expected metadata, three external roots, all auxiliary roots and
verified range states precede parent weights/rounds/finals. All five original
views have independent consumers at emitted points. Scalar reconstruction
and the expected real-row mask add no challenge. Whole t/h ranges, faithful
addition and zero endpoints establish U's whole bound; split ranges alone
do not. Closed column sides are at most511, below p/2. Padded rows and high
extensions stay zero. Runtime receipts, binding/FS, actual factor/branch
authentication, remaining output roles and native/model/private composition
remain additional.

The [output-division consumer](../../research/cqis-bounds/NORM-DIVISION.md)
inherits both complete quotient-product and biased-sum accounts. For N=2^a,
let bl/bh be byte-width exponents of the remainder/gap halves, H indicate
an active high half, and g count all active equality/strict carry families.
Additional A3 loss is[(22+18H+9g)*a+14*(bl+H*bh)+18g+16]/|K|.
Each additional nonlookup label has(10+8H+4g)*a+6*(bl+H*bh)+8g+8 draws.
Additional lookup dimensions are a+bl+1 twice, optional a+bh+1 twice and
g instances of a+3. Each retains its separate identity
((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. A3 terms are not squared with repetitions.
At full a14/bl3/bh2/H1/g7, additional A3 is1654/|K| with738 draws per
nonlookup label. Including both children gives3690/|K| and1636 draws per
label across26 lookup units. Complete expected metadata, seven external
roots, every auxiliary root and every verified child state precede parent
challenges. Both degree-one dimension a+4 relations consume their five
original views independently. Actual B and the initial strict one are masked
by expected real rows; these deterministic views add no challenge. Range
halves give exact whole r/gap<=Bmax-1. Byte bounds<=255 and Boolean carries
give sides<=511<p/2. Zero endpoints yield faithful equality and strict
remainder, retaining all inherited claims and high zeros. Runtime receipts,
binding/FS, same configured factors, selected branches, signed output and
native/model/private composition remain additional.

The [left-factor consumer](../../research/cqis-bounds/NORM-LEFT.md) has
N=2^a rows and eight byte columns. Let bl be the offset L-1 byte-width
exponent, g count active carry families and bg their byte-width exponents.
Total A3 loss is[(21+9g)*a+37+7bl+18g+7*sum(bg)]/|K|. Each nonlookup
label has(9+4g)*a+15+3bl+8g+3*sum(bg) draws. Lookup dimensions are
a+4, a+2, bl+1 and a+bg+3 for each family. Each retains its separate
identity ((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. No A3 term is squared with lookup repetitions.
At full a14/bl1/g2/bg1,1, A3 is640/|K| and each nonlookup label has278
draws; lookup dimensions are18,16,2,18,18. Complete expected metadata,
three external roots, every auxiliary root and verified range state precede
parent challenges. All nine original views are independently consumed,
including the three factor-byte views at zero product. Reconstructing
positive L from actual offset bytes adds no challenge. Whole input ranges,
closed carry caps and zero endpoints supply integer lifting; maximum side
is130815<p/2. All padded rows and six high quotient planes stay zero.
Runtime receipts, binding/FS, actual same-exponent factors, selected branches,
signed output and native/model/private composition remain additional.

The [signed-output consumer](../../research/cqis-bounds/NORM-SIGNED-OUTPUT.md)
retains complete canonical product-sign A3 numerator131a+148 and signed-Y
numerator43a+35 for N=2^a. Its degree-two parent adds3a, giving total
(177a+183)/|K|. Each nonlookup label has74a+75 draws. Preserve the ordered
lookup dimensions: six a+2, four a+3, then three a+2. Each retains its own
identity ((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. At full a14, total A3 is2661/|K| and each nonlookup
label has1111 draws across13 lookup units. A3 losses are not squared with r.
Complete expected metadata, six external roots and both verified child states
precede parent challenges. Actual verified byte/flag planes supply all three
original views, independently consumed at emitted points. Whole q<=32768
and Boolean s/sy bound each nonnegative side by32768<p/2. At q=0, canonical
product sign and both zero predicates remain enforced by the complete child;
only the equality of output/product signs becomes vacuous as rounding requires.
No child is gated by the output. Runtime receipts, binding/FS, same-magnitude
rounding composition, selected branches and native/model/private inference
remain additional.

The [configured-output wrapper](../../research/cqis-bounds/NORM-CONFIGURED-OUTPUT.md)
adds no random challenge. Sum the four complete child accounts in order:
configured factors, signed output, reciprocal product and selected left/division.
Keep each lookup identity and reduction separate. The first child retains
selection reduction6/|K|, product identity(k-1)/|K|, product reduction4b/|K|
and A3 numerator199+9b+18g for its static limb layout. Signed output adds
177a+183 and reciprocal product39a+85 to the A3 numerator, for N=2^a;
add the selected branch's complete A3/range/lookup account. No reduction is
squared with lookup repetitions. The wrapper preserves the factor-only
selection/product terms explicitly rather than dropping them during aggregation.
Complete expected function bytes, role ids, fifteen external roots, verified
branch, right-branch total root if present and all four verified states seed
the final transcript. Its draw map is empty. Exact source-root joins add no
algebraic loss conditional on binding. The verified factor bundle alone selects
the branch; every original consumer remains mandatory at zero products. The
left branch checks both unused qd/r roots against16N canonical zero slots.
Binding, FS/H, full normalized-interval/statistic/rsqrt joins, private composition
and model ownership remain additional. No profile or production cut is admitted.

The [complete RMSNorm arithmetic wrapper](../../research/cqis-bounds/NORM-COMPOSITION.md)
adds no random challenge. It retains seven complete child accounts in fixed order:
configured output, full statistic, numerator, mantissa product, normalization sum,
strict normalization remainder and reciprocal lookup. Concatenate the first six
children's ordered range-lookup identities, then the actual reciprocal identity
(98304/|K|)^r. Add its392r/|K| reduction to the six lookup-reduction totals.
Sum the inherited range/A3 numerators and retain the statistic A1 numerator
separately. Keep the factor selection reduction6/|K|. Four independent limb
product identity numerators remain in order (configured factors, numerator,
mantissa product, normalization sum); their sum over|K| is a union bound, not
one repeated identity. Add their four product-reduction numerators over|K|.
No reduction is squared with lookup repetitions. Full child receipts retain
every original/public claim and challenge event. The parent draw map is empty.
Its final seed binds complete expected function/role bytes, all nineteen roots
and seven verified states. Exact root joins add no algebraic loss conditional
on binding. N=ed*S+en*unit with positive expected epsilon and the same X source,
A=MD+R with bounded M and strict R<D, and complete (M,J) membership remain actual
consumers even at zero output. Binding, FS/H, physical/model ownership, native
lowering and private composition losses remain additional; no profile is admitted.

### Draft A3/A8 residual alignment consumer (Q26/Q31)

[Research scope](../../research/cqis-bounds/RESIDUAL-ALIGNED.md). With padded
N=2^a, output range width2^b and g statically nonzero four-column carry families,
retain six signed16 lookup identities at m=a+2, one output identity at a+b+1
and g carry identities at a+3. Each contributes ((2^m+255)/|K|)^r separately,
with unsquared reduction r*(f(m)+f(8)+3m)/|K|, f(m)=3m(m-1)/2+2m.
Complete range/A3 numerator is (97+9g)*a+76+7b+18g. This includes the parent's
degree-one A3 over8N, whose three phase losses are a+3,0,a+3. Its five original
views are independently consumed at their emitted points. Fixed expected role
and schema bytes, three external roots, auxiliary roots and verified child
states precede ZeroWeight and the Instance/Round/Final schedule. Parent draws
are a+3 per ZeroWeight/Sumcheck label; including signed/range children, totals
are (41+4g)*a+31+3b+8g for each label, excluding separate lookup schedules.
Carry caps are static, at most255; both byte-column sides are at most65535<p/2.
No runtime maximum establishes integer faithfulness. Binding, FS/H, private
composition and physical/model ownership remain additional. No production
profile, native control or complete residual/inference claim is admitted.

### Draft A3/A8 canonical residual numerator sign (Q26/Q31)

[Research scope](../../research/cqis-bounds/RESIDUAL-SIGN.md). Six complete
ranges O,M,s,g,c0,c1 retain lookup dimensions a+b_o+1,a+b_m+1,a+1,a+2,a+3,a+3,
where N=2^a and actual O/M range byte widths are2^b_o and2^b_m. Each separate
identity is ((2^m+255)/|K|)^r; its unsquared reduction is
r*(f(m)+f(8)+3m)/|K|, f(m)=3m(m-1)/2+2m. Range/A3 numerator totals
61a+7(b_o+b_m)+52. Parent A3s run in fixed order: terminal degree1 at a,
signed columns degree2 at a+3, canonical zero degree1 at a. Their phase
numerators sum to7a+9; all twelve original claims retain their consumers.
Expected schema/roles, three external roots, six auxiliary roots and verified
child states precede parent weights and Instance/Round/Final messages.
Parent draws per ZeroWeight/Sumcheck label are3a+3; full nonlookup totals
are27a+22+3(b_o+b_m), with lookup schedules accounted separately.
Natural carry bounds[-2,2], shifted to[0,4], and exact endpoints yield integer
column faithfulness with sides<=1534<p/2. Canonical zero uses actual byte sum
<=2040 and g+s<=2041, never a wide M31 residue or runtime fit. Binding, FS/H,
physical/model/private composition and full inference remain additional;
no production profile or native control credit is admitted.

### Draft A3/A8 residual magnitude rounding (Q26/Q31)

[Research scope](../../research/cqis-bounds/RESIDUAL-ROUNDING.md). Five complete
ranges M,q,r,c0,c1 retain lookup dimensions a+b_m+1,a+2,a+b_r+1,a+3,a+3,
where N=2^a and actual M/r range byte widths are2^b_m and2^b_r. Each identity
is ((2^m+255)/|K|)^rpt with separate unsquared reduction
rpt*(f(m)+f(8)+3m)/|K|, f(m)=3m(m-1)/2+2m. Complete range/A3 numerator is
49a+7(b_m+b_r)+49. Parent terminal and column A3s have degree1 and dimensions
a,a+3; their three-phase numerators total4a+6. All eight original claims
retain their actual-point consumers. Expected schema/roles, three external
roots, five auxiliary roots and five verified child states precede weights
and Instance/Round/Final messages. Parent draws per ZeroWeight/Sumcheck label
are2a+3; full nonlookup totals are22a+22+3(b_m+b_r), with lookup schedules
accounted separately. Natural carry[-129,2], encoded by adding129, has complete
range[0,131] and exact endpoints. Column sides<=66431<p/2 make M+h=q*B+r
integer-faithful. Expected fractions determine B and h; whole r<B, q<=32768
and M<=H remain actual range consumers. Binding, FS/H, native/model/private
composition and physical source ownership remain additional. No profile is
admitted and no production control or complete residual credit is claimed.

### Draft A3/A8 complete residual arithmetic composition (Q26/Q31)

[Research scope](../../research/cqis-bounds/RESIDUAL-COMPOSITION.md). Four complete
children retain aligned inputs, canonical numerator sign, magnitude rounding
and signed output. For N=2^a, actual O/M/r byte widths2^bo/2^bm/2^br and g
nonzero alignment carry families, retain all21+g independent lookup identities
and their original unsquared reductions. Complete range/A3 numerator is
(253+9g)*a+212+14*(bo+bm)+7*br+18g. The parent degree-two A3 q*(s-sZ)=0
contributes3a across its phases and retains all three original consumers.
Expected schema/roles, eight external roots and four verified child states
precede parent ZeroWeight and Instance/Round/Final messages. Parent draws are
a per ZeroWeight/Sumcheck label; full nonlookup totals are
(109+4g)*a+89+6*(bo+bm)+3*br+8g. Complete receipts preserve all lookup schedules.
The static parent product bound32768<p/2 and inherited static byte certificates
establish integer faithfulness; no child is omitted at q=0. Exact shared-root
joins add no algebraic error conditional on binding. Binding, FS/H, physical
source/model ownership, native lowering and private composition remain
additional. No production profile or native control credit is admitted.

### Draft A3/A6/A7 canonical rotary row consumer (Q26/Q31)

[Research scope](../../research/cqis-bounds/ROTARY-CONSUMER.md). Two complete
signed16 sources and four whole ranges retain ten lookup identities: six at
dimension a+2, then a+3,a+1,a+3,a+2, for padded row size N=2^a. Each contributes
((2^m+255)/|K|)^rpt independently, with unsquared reduction
rpt*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Four parent A3s at dimension a
have degrees2,1,1,2; phase numerators total10a. Complete range/A3 numerator is
132a+105. Parent draws are4a per ZeroWeight/Sumcheck label; complete nonlookup
totals are56a+43 each. All sixteen original claims retain actual-point consumers.
Expected schema, units, canonical A7 descriptor, absolute position, eight roots
and six verified child states precede parent weights and Instance/Round/Final
messages. Public coefficients are regenerated from that definition, including
their expected pairing and padding; no supplied coefficient row authorizes
acceptance. The fixed23171 envelope bounds the signed numerator by759267328;
M+8192<=759275520, g+s<=759267329 and q*16384+r<=536887295 stay below p/2.
Complete signed/range consumers remain mandatory at zero and in passthrough.
Binding, FS/H, physical/model ownership, native lowering and private composition
remain additional. No profile or NC-0106/0109 credit is admitted.

### Draft A3/A6 masked attention maximum consumer (Q26/Q31)

[Research scope](../../research/cqis-bounds/ATTENTION-MAXIMUM-CONSUMER.md).
For N=2^a and offset/difference widths2^bo/2^bd, eight complete ranges retain
separate lookup identities at dimensions a+3,3,a+bo+1,a+bd+1,a+bd+1 and three
a+3. Each contributes ((2^m+255)/|K|)^rpt with unsquared reduction
rpt*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Five parent A3s use dimensions
a+2,a+2,a+2,a,2 and degrees1,2,1,1,1. Parent numerator9a+18 and all20 original
consumers remain; total range/A3 numerator is72a+100+7bo+14bd. Parent draws
are4a+8 of each ZeroWeight/Sumcheck label; complete nonlookup totals are
32a+44+3bo+6bd each. Expected schema/positions/block/window, nine roots and
eight verified states precede weights and Instance/Round/Final messages.
The selected absolute ID has a checked complete opening against its expected
root and is required to be an allowed key. Its derived prefix and source
views retain their actual-point consumers. Public masks come from expected
metadata. All byte sides are bounded by511<p/2. The source translation
permits a final Boolean wrap at2^32; static S<2^31 and O<=2S establish signed
range faithfulness. Difference/prefix terminal carries must both be zero;
their sum<=2 cannot alias. Binding, FS/H, private selection, physical/model
ownership and key-set completeness remain additional. No production profile
or native NC-0500..0506 credit is admitted.

### Draft A3/A6 exponential index split consumer (Q26/Q31)

[Research scope](../../research/cqis-bounds/ATTENTION-EXP-INDEX.md). For N=2^a
and actual byte widths2^bu/2^bh/2^bl, four independent lookup identities use
dimensions a+bu+1,a+bh+1,a+bl+1,a+3. Each contributes
((2^m+255)/|K|)^rpt and an unsquared reduction rpt*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. One degree-one parent A3 at a+2 adds2a+4; total range/A3
numerator is38a+22+7*(bu+bh+bl). Parent draws are a+2 per ZeroWeight/Sumcheck
label, and complete nonlookup counts are17a+10+3*(bu+bh+bl) each. All five
original views have actual-point consumers, including shifted high zeros.
Expected maximum-instance metadata, exact function/representation, four roots
and four verified range states precede parent weights and Instance/Round/Final
messages. Four byte columns reconstruct u=2^k*h+l, with c=2^(k mod8)<=128,
carry<=c and zero initial/final carries; each side<=33023<p/2. Whole u/domain
and strict low-index caps enforce the inclusive endpoint. Composition joins
the actual verified maximum difference root without new draws and retains
that child's entire independent account. Binding, FS/H, private sources,
physical/model ownership and canonical table membership remain additional.
No production profile or native NC-0500..0506 credit is admitted.

### Draft A3/A6 canonical exponential output consumer (Q26/Q31)

[Research scope](../../research/cqis-bounds/ATTENTION-EXP.md). For N=2^a,
retain all index/range lookup identities separately at their actual dimensions
m: ((2^m+255)/|K|)^rpt, plus unsquared rpt*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. Every complete canonical two-column lookup with T valid
rows adds ((N+2T-1)/|K|)^rpt and unsquared
rpt*(F(a)+F(ceil(log2 T))+3a)/|K|. File padding is excluded; fraction-tree
neutral padding stays internal. Direct/product/corrected paths have3/10/13
independent lookup units. The input-indexed correction is a full domain table.

Let bu,bh,bl be actual input/index byte exponents, bp the output/value exponent,
and br the remainder exponent. Total range/A3 numerators are18a+7*(bu+bp),
77a+22+7*(bu+bh+bl)+21bp+7br, and97a+22+7*(bu+bh+bl)+28bp+7br respectively.
Their parent numerators are0,3a,5a, retaining0/4/8 actual original consumers.
Complete nonlookup ZeroWeight/Sumcheck draws per label are8a+3*(bu+bp),
34a+10+3*(bu+bh+bl)+9bp+3br, and43a+10+3*(bu+bh+bl)+12bp+3br; parent
counts are0,a,2a. Each canonical lookup draws rpt Beta/Alpha, rpt*(a+t)
Gamma/Fold and rpt*(a*(a-1)/2+t*(t-1)/2+a) Sumcheck, t=ceil(log2 T).
Multiplicity commitments precede all challenge pairs. No unit challenge is
needed because b=m=a; no reduction term is squared by lookup repetition.

Expected maximum metadata/function/representation, external/auxiliary/tuple
roots and all verified child states precede parent weights and A3 messages.
Tuple columns equal actual verified byte views, including masked zeros.
Static Q<=16384 bounds product sides by Q^2+Q-1<p/2 and correction sides by
Q+3<p/2. Strict remainder r<Q proves floor; correction offset in[0,3] and
expected mask reconstruct signed C. Direct/correction inputs satisfy u<=2^15,
so their signed field lifts are injective. Actual maximum composition retains
its entire independent account without extra join draws. Binding, FS/H,
physical/model ownership, native/private lowering remain additional. No
production profile or native NC-0500..0506 credit is admitted.

### Draft A3/A6 consumed probability row sum (Q26/Q31)

[Research scope](../../research/cqis-bounds/ATTENTION-PROBABILITY-SUM.md).
For source dimension a and source/scalar byte exponents bp/bz, two complete
range lookup units use dimensions a+bp+1 and bz+1. Each independently retains
((2^m+255)/|K|)^rpt and unsquared rpt*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. Range/A3 numerator is9a+7bp+7bz; the separate degree-one
sum A1 adds a/|K|. Its one original claim has an independent full-hypercube
consumer at the exact emitted point. Full nonlookup draws are4a+3bp+3bz
ZeroWeight and5a+3bp+3bz Sumcheck; the parent draws a Sumcheck challenges.
Expected complete row/mask/E metadata, two external roots, compact scalar root
and both verified range states precede parent Instance/Round/Final messages.
Static K*2^E<=2^28<p/2 bounds both sides; no M31 alias can satisfy the actual
scalar range. Full output binding retains four canonical byte leaves even when
the compact range uses one or two. Standalone zero sums do not skip any child
or the dimension-zero final equation. Whole-row positivity requires the actual
attained maximum and complete exponential proofs on the same source roots;
all their independent accounts remain additional, with no extra join draws.
Binding, FS/H, physical/model ownership and native/private lowering remain
additional. No production profile or native NC-0503 credit is admitted.

### Planned restored-value consumer (Q26/Q31; Draft RFC-0004 A3/A6)

Before implementation, let a=log2(padded value entries), ar=log2(padded key
positions), and bo=log2(compact output byte width). Retain the complete
signed8 source account. Static restoration adds two complete wide ranges
and one degree-two A3, for total numerator 64a+9+7bo and 27a+4+3bo draws
per nonlookup label. Ordered lookup dimensions are a+1,a+1,a+2,a+1,a+bo+1.
Dynamic restoration also consumes scale, Boolean nonzero and predecessor
ranges on positions, one degree-two A3 over 2R predicate entries, and one
over N value entries for zero-scale codes. Its total A3 numerator is
67a+30ar+26+7bo and each nonlookup label has 28a+13ar+11+3bo draws. Append
lookup dimensions ar+2,ar+1,ar+2. Each unit retains its separate identity
((2^m+255)/|K|)^r and unsquared reduction r*(F(m)+F(8)+3m)/|K|, where
F(m)=3m(m-1)/2+2m. Complete expected metadata, external/auxiliary roots
and all verified child states precede parent weights, rounds and finals.
The planned restoration relation has five actual original-point consumers;
dynamic predicates and zero-scale codes add four and two respectively.

These formulas are not runtime evidence. Tests must verify each receipt
and challenge count before acceptance. Actual prepared-row source ownership,
Binding/H/FS, PCS/ZK, weighted-sum composition and native inference remain
additional obligations. No production profile or NC credit is granted.
