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
