# Two-bit selection-source question (Q20)

Status: research under Draft RFC-0006 A4. E3-06 retains every original criterion.
No private commitment format or joint ZK construction is admitted here.

Question: can two-bit symbols reduce the existing index source's message size
while actual degree-at-most-four reductions consume every virtual bit claim?
The committed source remains one tensor; its unpacked bit tensor is virtual.

Security properties: canonical symbol membership, padding and integer range;
all source and selection claims reach the same original source; no field alias
or substitution of a polynomial evaluated at an MLE for the MLE of that polynomial.
Cost terms: original message cells, c_sc/T_misc, proof elements and all openings.
The proposed consumer uses a source-plane view for claims with Boolean plane
coordinates, keeping these reductions linear in the accessed source cells.

Kill criteria: an accepted false source/selection statement under actual original
consumption; degree above four; unaccounted challenges; discarded claims; hidden
storage, preparation, opening or repeated full-tensor work. Private PCS, joint
masking and format selection remain separate obligations.

## Representation and actual consumers

Let a be the source-grid bit count, N=2^a, n its real row count, k in 0..63,
and C in [1,2^k]. Write Mb for the least power of two >=max(1,k), and Mp for
the least power of two >=max(1,ceil(k/2)). Db=a+log2(Mb)<=63 and
Dp=a+log2(Mp). There are at most 63 source axes. P has Mp plane-major source
grids; each symbol stores the high bit first, then the low bit. The bit tensor
F is the virtual Mb-plane tensor used by the previous source study.

Define
`H(P)=(-2P^3+9P^2-7P)/6` and `L(P)=P-2H(P)`. Their values on those four
symbols 0,1,2,3 are precisely the high/low Boolean bits, and P=2H+L holds for
every field value. For k>=2, F's
planes 2j and 2j+1 contain H(P_j) and L(P_j). For k=0/1 only H is present;
an additional A3 `P(P-2)=0`, degree two, forces the absent low bit to zero.
The previous bit-source proof enforces F's Booleanity, grid/plane padding and
range. Thus for k>=2 both H and L are Boolean everywhere, including zero padded
cells, so P=2H+L forces P into 0..3. The ordinary sum is at most 3<p/2;
there is no distinct canonical field alias. No separate membership proof is
needed. For k<2 the absent-bit relation gives P in {0,2}. For k=0 the core
also forces H=0, so the unique dummy symbol is zero.
For larger k both bits of every padded symbol are zero. No wide M31 residue
represents the whole integer: its canonical ordered bits define it.

Every F final is now an obligation to resolve, not a commitment opening. Split
its plane point into pair-plane coordinates u and the last bit selector theta;
keep source-row coordinates r. For k<2 use theta=0. The exact relation is

`F(u,theta,r)=sum_z eq((u,r),z)*((1-theta)*H(P(z))+theta*L(P(z)))`.

It is an actual A1 with degree four, not evaluation of the cubic at P(u,r).
The verifier recomputes the final equality value and exports the actual P final.
When all coordinates of u are Boolean, the same relation restricts to that one
pair plane and sums over only a variables. Its P-view final maps to the original
point `bits(pair_plane)||row_point`. Otherwise it sums over Dp variables and
exports that full original point. The dimension and mapping come from the
expected F claim, never the proof. Zero cubic coefficients retain degree four.
Range and selection bit claims always have Boolean plane coordinates. The two
general bit-core claims may use Dp; they can also restrict if their prefix is
Boolean. No original is discarded when the extraction polynomial is insensitive
to a changed symbol.

The prover constructs F from P, obtains the core's actual claims without changing
its messages, and supplies every resolver. Stage composition uses the actual
private coefficient stage and its weighted-selection receipt, then resolves all
k bit claims against P. The verifier fixture receives P and the stage originals,
not the integer vector or F as an authentication oracle. P and tensor bytes are
fixed in its public context before challenges. A real private PCS must consume
every P claim against one previously fixed commitment. Unmasked evaluations,
including scalar bits, provide no privacy or joint simulator.

## Framing and namespaces

PairedSource is `stele/v0.1/research/onehot/pairs`. Its payload is
`u8(1),u8(d),u8(2),u64(source_id),u8(axis_count),each(u8(bits),u64(real)),
u8(k),u64(C),u64(b),u64(t)`, little-endian; at most 604 bytes, no source values.
The existing Source frame follows later for the virtual F with id t+256.

Reserve an aligned 512-invocation block b and aligned 1024-tensor block t, both
fully within u64. The original P id lies outside the tensor block. The bit core
uses b..b+127 and t..t+255 unchanged. The absent-low relation uses b+257.
Resolver ordinal i uses b+128+i, equality id t+257+i and, for a plane view,
tensor id t+385+i. Source resolvers occupy ordinals 0..64; selection uses
65..127. Exact counts come from their actual receipts. F and every view/mask
remain uncommitted. Linkage checks source/layout/k/C and full block separation
from the stage's 65 invocations and its original/output/coefficient tensor ids.
Complete authenticated plan/semantic-axis identity is still required. Failure
after an absorb invalidates the attempt; no rollback or retry is provided.

## Accounting and cost comparison

Put e=1 when C<2^k and l=1 when k<2. Let m0,m1 be the two general resolvers'
actual dimensions, each at most Dp. Source validity has exact conditional
numerator `3la+7Db+3ea(k+1)+4(m0+m1+eka)` over |K|. Its upper bound is
`8Dp+7Db+3la+ea(7k+3)`. Exact draws are
`2la+4Db+ea(k+2)+m0+m1+eka`. Keep every A3 phase record, including zero
skip records; every resolver is an A1 degree-four record with its derived m_i.
The k stage-selection resolvers add 4ak to the numerator and ak draws, beyond
the existing stage/selection losses. Only existing ZeroWeight/Sumcheck draws
are used; no RLC, skip draw or challenge kind is added. Source fixation, actual
PCS/opening batching, FS/H and joint ZK losses are additional.

Source proof field payload is
`7Db+8+5(m0+m1)+l(3a+1)+e(3a+2+k(9a+5))` K elements, excluding fixed
metadata and wire framing. Selection resolution adds k(5a+2). There are
2+l+ek original source claims, plus k when composed with selection.

For k>=2, Mp=Mb/2: the prospective original message is 4MpN M31 bytes versus
4MbN for bit planes. At k=17 with N=n it is 64n bytes versus 128n for bit planes
and 8n for u64 capture. This is still eight-fold expansion over that capture.
These are size formulas, not benchmarks, and exclude encoding, Merkle and blinding.
For k=0/1 the message does not shrink. No new cut or format has been accepted.

Only two general resolvers can scan MpN cells. Each range/selection resolver
scans N cells of its known pair plane, including its equality preparation.
Packed proving, including the unchanged bit core, remains
O((Mb+k+Mp)N+n*s+k*(Db+s+1)), for s source axes, including point/metadata work;
conversion costs O(MbN+n*(s+k)).
Conditional verification is O(Db+s+k*(Db+s+1)), excluding actual openings.
Direct reference consumption of q claims costs O(q*MpN*(Dp+1)). The preparation
cap is `(2Mb+2k+2+Mp)N<=2^18` K payload cells before scanning source values.
It counts the original P and the bit core's prepared payloads; unfolding/folding
scratch, claim/context/proof bytes and Python objects are additional. F is still
materialized for proving, so message savings do not halve live working memory.
No fitted constant or weight pass changes; actual costs remain to be measured
with all bindings enabled before choosing a representation.
Review removed a redundant standalone symbol-membership proof: the bit core and
actual extraction consumers already establish membership. This avoids 5Dp/|K|
loss, 2Dp draws, 5Dp+1 proof elements and one original opening per source.

## Evidence and recommendation

Run `uv run --locked --script research/stacked-gkr/check_paired_source.py`.
Both fields pass 64 seeded source proofs and eight actual stage compositions,
checking all original consumers, exact SC records, challenge order, payload sizes
and continuation states. Digest:
`c5bb271da3040191ce8fb7a53a8273d689174749930f13cdbcb17ecc6ee22d5b`.
Checks include every two-bit symbol, 63-bit indices, all distinct paired planes
over six real rows, zero-width axes, exact independent frame bytes, maximal
identifier blocks and capacity/scope rejection. False symbol, absent/spare bit,
padding, range and 0/p substitution checks run actual reducers; forged scalar
symbol finals for that alias also fail at the actual source consumer. Changed equality
and unused original finals reach their named consumers. Cubic cancellation keeps
degree four; general and single-plane queries use their derived dimensions.
Omitting only PairedSource changes and rejects a real successor A1 final.
The legacy bit-source digest remains unchanged.

Recommendation: retain this candidate as a concrete payload/proof-work comparison;
measure complete costs and resolve private PCS/joint masking before any adoption.
Research checks earn no production NC credit. See the
[same-author review](../../agents/reviews/paired-source-study.md).
