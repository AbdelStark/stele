# Consumed attention exponential outputs (Q26 / Q31)

Can actual bounded score differences produce the configured exponential bytes,
with complete canonical membership, exact output arithmetic and canonical
masked zeros? This is Draft RFC-0004 A3/A6 research for RFC-0021 §2.1 and
RFC-0009 A1. Costs are c_x/c_sc/c_lu/T_misc. Kill the design if a supplied or
partial table, padded tuple, wrong representation, source substitute, false
product/remainder, correction or masked value is accepted.

Expected metadata fixes an attention-maximum Spec and an exact exponential
Representation. B/F must match the maximum schema. Direct nearest, product
and corrected nearest retain their entire supported parameter domains. Source
and output roots are independently expected. At most16384 actual keys and
absolute span2^20 remain. The maximum Spec derives causal/window/block masks;
its actual proof and model/key-set ownership remain separate source obligations.

Split modes consume the complete [index proof](ATTENTION-EXP-INDEX.md), joining
its actual u root. Direct mode consumes that same bounded byte source with its
own complete range. All output values lie in[0,Q], Q=2^E<=16384. Product and
corrected modes also range H,L<=Q and remainder r<Q. Corrected mode ranges the
base quotient<=Q and correction offset C+1 in[0,3]. Every masked/padded value
has cap zero. Product uses the output itself as quotient; no duplicate quotient
source is introduced. Every range and index child remains mandatory at zero.

Each expected component descriptor generates its complete canonical table.
Only its actual valid rows enter membership; canonical file padding is not a
valid tuple. This matters for high/direct tables, where(0,0) would falsely
admit exp(0)=0. Internal fraction-tree padding retains(0,1) neutral leaves.
H/L lookups consume actual verified h/l and value byte views. Direct/correction
lookups consume(-u,value) with u<=2^15, so their signed lift is injective.
Every provided lookup column must equal these actual views, including masked
entries. Expected mask selectors exclude those entries from membership;
complete ranges enforce their canonical zeros. Tuple claims, multiplicities
and table denominators retain their complete consumers.

One degree-two A3 proves H*L=Q*q+r, with no rounding bias. Corrected mode adds
one degree-one A3 proving output=q+offset-mask. Its actual correction lookup
returns offset-mask, including negative corrections; it never substitutes a
four-value table for input-indexed membership. Product sides are bounded by
Q^2+Q-1<=268451839<p/2, and correction sides by Q+3. Direct mode needs no
additional A3. All parent originals retain actual-point consumers. Final
output zeros are enforced even when function values at zero equal Q.

Namespace before code: identity<2^42, base=2^63+2^20*identity, disjoint from
the maximum instance's span. The index child256*identity+1 occupies4096..8192.
Parent wide children16384*identity+1..6 occupy64..448. Auxiliary sources use
base+1..7, tuple view ids16..21 and multiplicities24..29. Parent A3 views32..39
and ids65536*identity+512/+513 are disjoint from child roles. The output id is
distinct from maximum roles and outside both spans. Expected metadata,
function/representation, external/auxiliary/tuple roots and every verified
child/lookup state precede the parent transcript. No supplied receipt or table
hash authorizes acceptance. Table caches are bounded and immutable.

Let N=2^a, input/index byte exponents bu,bh,bl, output/value exponent bp and
remainder exponent br. Preserve every range/index lookup identity separately:
((2^m+255)/|K|)^rpt, with unsquared reduction rpt*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. Each canonical two-column table with T valid rows adds its
own ((N+2T-1)/|K|)^rpt and unsquared reduction
rpt*(F(a)+F(ceil(log2 T))+3a)/|K|. Full range/A3 numerators are:

- Direct:18a+7*(bu+bp).
- Product:77a+22+7*(bu+bh+bl)+21bp+7br, including parent3a.
- Corrected:97a+22+7*(bu+bh+bl)+28bp+7br, including parent5a.

Nonlookup ZeroWeight/Sumcheck counts per label are respectively
8a+3*(bu+bp),34a+10+3*(bu+bh+bl)+9bp+3br, and
43a+10+3*(bu+bh+bl)+12bp+3br. Parent counts are0,a,2a respectively.
Actual maximum-source composition retains that child's full independent
account. Binding, FS/H, physical/model and private losses remain additional.

Tests first:10000 independent positive-Taylor/reciprocal and NumPy row checks,
all representations, output widths, E=0, nonzero corrections, inclusive
endpoints, masked/padded zeros and full namespace geometry. Attack every root,
lookup source/final/multiplicity, parent original, canonical table, padded
tuple, product/remainder and correction. Compose with an actual maximum proof.
Require matrices in both fields/repetition counts and separate16384-row
product/direct/corrected proofs, then all required local gates before publication.

Continue Q26/Q31 with sums, value products and complete attention composition.
Native/private lowering, physical/model source ownership, full inference,
fidelity and original task/control criteria remain open. No benchmark, extra
weight pass, new cut, profile or production control credit is claimed.

The10000-case independent positive-Taylor/reciprocal and NumPy corpus passed
(seed2732), including all correction values{-1,0,1,2}, all representations,
E=0/7/8/14, inclusive B=31 product and B=15 nearest endpoints, masked/padded
zeros and namespace boundaries. Frozen SHA-256:
`23c13d63d90b88d9756f41249301b4ea55e302b5c04f1cb4446ab34d91cc26c9`.
Primary root/lookup-final/multiplicity/authority/metadata controls passed.
Remaining original/boundary/table/source-composition suites, full matrix,
three full-row paths and required local gates remain pending.

All eight parent-original controls also passed. The first strict-remainder
fixture at E=8 grew from one byte to two and failed construction with
OpeningShape; this was not a verifier rejection. The repaired E=7 fixture
keeps one byte and targets r=Q with quotient reduced by one, preserving the
product equality. The first log remains retained. No verifier change or repeat
of passed primary/original suites was needed.

The repaired strict-remainder control passed, as did masked/padded output and
correction-source substitutions. The complete canonical-table attack and
remaining direct/zero/composition/matrix suites are still running.

The genuinely corrupted complete high table rejected at
HighLookup:FinalEvaluationMismatch. Its two-row fraction tree reaches a
zero-variable sumcheck, whose changed transcript fails the final equation.
The first test expected RoundSumMismatch; only that exact diagnostic changed.
The failed log and successful boundary sentinel are retained.

All three genuine table attacks passed after correcting that diagnostic.
Direct-nearest source roots, compressed finals and output substitutions reject.
Corrected E=0 retains every mandatory range, index, lookup and parent A3.
An actual attained-maximum proof composes through the exact difference root,
indices and canonical exponentials; another valid maximum proof with a changed
difference cannot substitute. The16-case field/repetition matrix is running;
three full-row proofs and required local gates are queued once.
